//! VMware ESXi configuration, via the `esxi` parser: the host's settings
//! (`esx.conf`), the VMs registered on it (`vmInventory.xml`), each VM's
//! settings (`.vmx`: disks, networks, encryption, a console open to VNC)
//! and snapshots (`.vmsd`, with their creation times).

use esxi::{Artifact, HostConfig, InventoryEntry, Snapshot, Vm};
use model::adapter::{Adapter, Confidence, Input, ParseError, Sink, Skipped};
use model::{Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Value};

/// The host's configuration.
pub const HOST: Namespace = Namespace::new("esxi.host");
/// VMs registered on the host.
pub const INVENTORY: Namespace = Namespace::new("esxi.inventory");
/// VM settings.
pub const VM: Namespace = Namespace::new("esxi.vm");
/// VM snapshots.
pub const SNAPSHOT: Namespace = Namespace::new("esxi.snapshot");

/// One record per host configuration, registered VM, VM and snapshot.
#[derive(Debug, Default, Clone, Copy)]
pub struct EsxiAdapter;

impl Adapter for EsxiAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "esxi",
            version: esxi::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[HOST, INVENTORY, VM, SNAPSHOT]
    }

    /// By name, and text that looks like the file (settings, or the
    /// inventory's root).
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        let text = String::from_utf8_lossy(head);
        let looks = match esxi::detect(name) {
            Some(Artifact::Inventory) => text.contains("<ConfigRoot"),
            Some(_) => text
                .lines()
                .find(|l| !l.trim().is_empty())
                .is_some_and(|l| l.contains('=')),
            None => false,
        };
        if looks {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        let (problems, records) = match esxi::detect(input.name) {
            Some(Artifact::EsxConf) => {
                let host = esxi::read_esx_conf(input.data);
                let problems = host.settings.problems.clone();
                (problems, vec![self.host(input, &host)])
            }
            Some(Artifact::Inventory) => {
                let inventory = esxi::read_inventory(input.data);
                let records = (0u64..)
                    .zip(&inventory.entries)
                    .map(|(i, e)| self.inventory(input, i, e))
                    .collect();
                (inventory.problems, records)
            }
            Some(Artifact::Vmx) => {
                let vm = esxi::read_vmx(input.data);
                let problems = vm.settings.problems.clone();
                (problems, vec![self.vm(input, &vm)])
            }
            Some(Artifact::Vmsd) => {
                let snapshots = esxi::read_vmsd(input.data);
                let records = snapshots
                    .snapshots
                    .iter()
                    .map(|s| self.snapshot(input, s, snapshots.current))
                    .collect();
                (snapshots.problems, records)
            }
            None => return Err(ParseError::at(0, "not an ESXi file this parser reads")),
        };
        for reason in problems {
            sink.skipped(Skipped {
                locator: Locator::ByteOffset(0),
                reason,
            });
        }
        for record in records {
            sink.record(record);
        }
        Ok(())
    }
}

impl EsxiAdapter {
    fn new_record(self, input: &Input<'_>, namespace: Namespace, row: u64) -> Record {
        Record::new(
            input.evidence,
            namespace,
            Locator::TableRow {
                table: namespace.as_str().to_owned(),
                row,
            },
            self.parser(),
        )
    }

    fn host(self, input: &Input<'_>, host: &HostConfig) -> Record {
        let mut record = self.new_record(input, HOST, 0);
        let mut fields = Fields::new();
        text(&mut fields, "Hostname", host.hostname.as_deref());
        text(&mut fields, "Uuid", host.uuid.as_deref());
        if !host.log_hosts.is_empty() {
            text(&mut fields, "LogHosts", Some(&host.log_hosts.join(", ")));
        }
        flag(&mut fields, "SshAllowed", host.ssh_allowed);
        flag(
            &mut fields,
            "ShellWarningSuppressed",
            host.shell_warning_suppressed,
        );
        fields.insert(
            "Settings".into(),
            Value::UInt(host.settings.settings.len() as u64),
        );
        record.fields = fields;
        record.facets = Facets {
            host_name: host.hostname.clone(),
            ..Facets::default()
        };
        record.summary = format!(
            "ESXi host {}: SSH {}, logs to {}",
            host.hostname.as_deref().unwrap_or("?"),
            match host.ssh_allowed {
                Some(true) => "allowed",
                Some(false) => "blocked",
                None => "unset",
            },
            if host.log_hosts.is_empty() {
                "nowhere set".to_owned()
            } else {
                host.log_hosts.join(", ")
            }
        );
        record
    }

    fn inventory(self, input: &Input<'_>, index: u64, entry: &InventoryEntry) -> Record {
        let mut record = self.new_record(input, INVENTORY, index);
        let mut fields = Fields::new();
        text(&mut fields, "EntryId", entry.id.as_deref());
        text(&mut fields, "VmId", entry.obj_id.as_deref());
        text(&mut fields, "VmxPath", entry.vmx_path.as_deref());
        record.fields = fields;
        record.facets = Facets {
            file_path: entry.vmx_path.clone(),
            ..Facets::default()
        };
        record.summary = format!(
            "ESXi VM {} registered: {}",
            entry.obj_id.as_deref().unwrap_or("?"),
            entry.vmx_path.as_deref().unwrap_or("?")
        );
        record
    }

    fn vm(self, input: &Input<'_>, vm: &Vm) -> Record {
        let mut record = self.new_record(input, VM, 0);
        let mut fields = Fields::new();
        text(&mut fields, "DisplayName", vm.display_name.as_deref());
        text(&mut fields, "GuestOs", vm.guest_os.as_deref());
        text(&mut fields, "BiosUuid", vm.bios_uuid.as_deref());
        text(&mut fields, "VcUuid", vm.vc_uuid.as_deref());
        if !vm.disks.is_empty() {
            text(&mut fields, "Disks", Some(&vm.disks.join(", ")));
        }
        let nics: Vec<String> = vm
            .nics
            .iter()
            .map(|n| {
                format!(
                    "{} on {} ({})",
                    n.name,
                    n.network.as_deref().unwrap_or("?"),
                    n.mac.as_deref().unwrap_or("?")
                )
            })
            .collect();
        if !nics.is_empty() {
            text(&mut fields, "Nics", Some(&nics.join(", ")));
        }
        fields.insert("Encrypted".into(), Value::Bool(vm.encrypted));
        fields.insert("VncEnabled".into(), Value::Bool(vm.vnc.is_some()));
        if let Some(vnc) = &vm.vnc {
            if let Some(port) = vnc.port {
                fields.insert("VncPort".into(), Value::UInt(u64::from(port)));
            }
            fields.insert("VncPasswordSet".into(), Value::Bool(vnc.password_set));
        }
        record.fields = fields;
        record.summary = format!(
            "ESXi VM {} ({}){}",
            vm.display_name.as_deref().unwrap_or("?"),
            vm.guest_os.as_deref().unwrap_or("?"),
            if vm.vnc.is_some() {
                ", console open to VNC"
            } else {
                ""
            }
        );
        record
    }

    fn snapshot(self, input: &Input<'_>, snapshot: &Snapshot, current: Option<u32>) -> Record {
        let row = snapshot.uid.map_or(0, u64::from);
        let mut record = self.new_record(input, SNAPSHOT, row);
        if let Some(time) = snapshot.created {
            record
                .times
                .push(RecordTime::new(TimeKind::Created, "Created", time));
        }
        let mut fields = Fields::new();
        text(&mut fields, "Name", snapshot.name.as_deref());
        text(&mut fields, "Description", snapshot.description.as_deref());
        text(&mut fields, "File", snapshot.file.as_deref());
        if let Some(uid) = snapshot.uid {
            fields.insert("Uid".into(), Value::UInt(u64::from(uid)));
            fields.insert("Current".into(), Value::Bool(current == Some(uid)));
        }
        if let Some(parent) = snapshot.parent {
            fields.insert("Parent".into(), Value::UInt(u64::from(parent)));
        }
        if !snapshot.disks.is_empty() {
            text(&mut fields, "Disks", Some(&snapshot.disks.join(", ")));
        }
        record.fields = fields;
        record.summary = format!(
            "ESXi snapshot {}{}",
            snapshot.name.as_deref().unwrap_or("?"),
            snapshot
                .description
                .as_deref()
                .map(|d| format!(": {d}"))
                .unwrap_or_default()
        );
        record
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}

fn flag(fields: &mut Fields, name: &str, value: Option<bool>) {
    if let Some(value) = value {
        fields.insert(name.into(), Value::Bool(value));
    }
}
