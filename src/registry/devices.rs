//! SYSTEM: USB devices of the current control set, and `MountedDevices`.

use std::fmt::Write as _;

use common::time::Ts;
use model::{Facets, Fields, RecordTime, TimeKind, Value};
use registry::mounted::{self, Binding, Mount, Target};
use registry::usb::{self, Device, DeviceTime, TimeSource};
use registry::Hive;

use super::{insert_texts, Out, MOUNTED_DEVICES, USB};

/// A device time's field name, marked when the key's last write stands in.
fn time_field(name: &str, time: DeviceTime) -> String {
    match time.source {
        TimeSource::Property => name.to_owned(),
        TimeSource::KeyLastWritten => format!("{name}(KeyLastWritten)"),
    }
}

/// A binding as text: `MBR disk 0xA5FFC3BD offset 1048576`, the GUID, the
/// device path, printable bytes as text and others in hexadecimal.
fn binding_text(binding: &Binding) -> String {
    match binding {
        Binding::Mbr {
            disk_signature,
            offset,
        } => format!("MBR disk 0x{disk_signature:08X} offset {offset}"),
        Binding::Gpt(guid) => format!("GPT partition {guid}"),
        Binding::Device(path) => path.clone(),
        Binding::Other(bytes) if bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ') => {
            String::from_utf8_lossy(bytes).into_owned()
        }
        Binding::Other(bytes) => bytes.iter().fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        }),
    }
}

impl Out<'_, '_> {
    /// USB devices and `MountedDevices`, in SYSTEM.
    pub(super) fn devices(&mut self, hive: &Hive<'_>) {
        let Ok(Some(set)) = hive.current_control_set() else {
            return;
        };
        let found = usb::devices(hive, &set);
        self.problems(found.problems);
        for device in &found.entries {
            self.device(device);
        }
        let found = mounted::read(hive);
        self.problems(found.problems);
        for mount in &found.entries {
            self.mount(mount);
        }
    }

    fn device(&mut self, device: &Device) {
        let mut record = self.keyed(USB, &device.key, None, device.key_last_written);
        for (kind, name, time) in [
            (TimeKind::Other, "Installed", device.installed),
            (
                TimeKind::FirstSeen,
                "FirstInstalled",
                device.first_installed,
            ),
            (TimeKind::LastSeen, "LastArrival", device.last_arrival),
            (TimeKind::LastSeen, "LastRemoval", device.last_removal),
        ] {
            if let Some(time) = time {
                record.times.push(RecordTime::new(
                    kind,
                    time_field(name, time),
                    Ts::from_filetime(time.filetime),
                ));
            }
        }
        record.facets = Facets {
            service_name: device.service.clone(),
            ..Facets::default()
        };
        let mut fields = Fields::new();
        fields.insert("Bus".into(), Value::from(device.bus.name()));
        fields.insert("Device".into(), Value::from(device.device.as_str()));
        fields.insert("Serial".into(), Value::from(device.instance.as_str()));
        fields.insert(
            "SerialIsUnique".into(),
            Value::Bool(device.serial_is_unique()),
        );
        let description = device
            .description
            .as_deref()
            .map(|d| usb::readable(d).to_owned());
        insert_texts(
            &mut fields,
            &[
                ("Type", device.kind.as_ref()),
                ("Vendor", device.vendor.as_ref()),
                ("Product", device.product.as_ref()),
                ("Revision", device.revision.as_ref()),
                ("FriendlyName", device.friendly_name.as_ref()),
                (
                    "BusReportedDescription",
                    device.bus_reported_description.as_ref(),
                ),
                ("DeviceDesc", description.as_ref()),
                ("Service", device.service.as_ref()),
                ("ParentIdPrefix", device.parent_id_prefix.as_ref()),
                ("LocationInformation", device.location.as_ref()),
                ("ContainerID", device.container_id.as_ref()),
                ("DiskId", device.disk_id.as_ref()),
            ],
        );
        if let Some(time) = device.last_arrival {
            let source = match time.source {
                TimeSource::Property => "property 0066",
                TimeSource::KeyLastWritten => "instance key's last write (no 0066 property)",
            };
            fields.insert("LastArrivalSource".into(), Value::from(source));
        }
        if !device.mounts.is_empty() {
            fields.insert(
                "Mounts".into(),
                Value::List(
                    device
                        .mounts
                        .iter()
                        .map(|m| Value::from(m.as_str()))
                        .collect(),
                ),
            );
        }
        record.fields = fields;
        let name = device
            .friendly_name
            .as_deref()
            .or(device.bus_reported_description.as_deref())
            .or(description.as_deref())
            .unwrap_or(&device.device);
        let letters: Vec<&str> = device
            .mounts
            .iter()
            .filter_map(|m| m.strip_prefix(r"\DosDevices\"))
            .collect();
        record.summary = format!(
            "{} device {name} (serial {})",
            device.bus.name(),
            device.instance
        );
        if !letters.is_empty() {
            let _ = write!(record.summary, " · {}", letters.join(", "));
        }
        self.sink.record(record);
    }

    fn mount(&mut self, mount: &Mount) {
        let mut record = self.keyed(
            MOUNTED_DEVICES,
            "MountedDevices",
            Some(&mount.name),
            mount.key_last_written,
        );
        let binding = binding_text(&mount.binding);
        let mut fields = Fields::new();
        fields.insert("Name".into(), Value::from(mount.name.as_str()));
        fields.insert("Binding".into(), Value::from(binding.as_str()));
        let target = match &mount.target {
            Target::DriveLetter(letter) => {
                fields.insert("DriveLetter".into(), Value::Text(format!("{letter}:")));
                format!("{letter}:")
            }
            Target::Volume(guid) => {
                fields.insert("VolumeGuid".into(), Value::from(guid.as_str()));
                format!("volume {guid}")
            }
            Target::Other => mount.name.clone(),
        };
        if let Some((bus, device, instance)) = mount.binding.device_parts() {
            fields.insert("DeviceBus".into(), Value::from(bus));
            fields.insert("Device".into(), Value::from(device));
            fields.insert("Serial".into(), Value::from(instance));
        }
        if !mount.same_binding.is_empty() {
            fields.insert(
                "SameBinding".into(),
                Value::List(
                    mount
                        .same_binding
                        .iter()
                        .map(|m| Value::from(m.as_str()))
                        .collect(),
                ),
            );
        }
        record.fields = fields;
        record.summary = format!("Mounted device {target} → {binding}");
        self.sink.record(record);
    }
}
