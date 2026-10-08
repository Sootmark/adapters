//! Windows Server's User Access Logging (`Windows\System32\LogFiles\Sum`),
//! via the `ual` parser: one record per client's use of a role during the
//! year (who, from where, how often, first and last, which days), per
//! role's first and last use, per name resolution and per hosted virtual
//! machine; a year's database is read with `SystemIdentity.mdb` beside it
//! for the roles' names. `SystemIdentity.mdb` itself gives the server's
//! identity.

use common::time::{civil_from_days, days_from_civil};
use model::adapter::{Adapter, Companion, Confidence, Input, ParseError, Sink, Skipped};
use model::{
    Facets, Fields, Locator, Namespace, ParserInfo, Record, RecordTime, TimeKind, Ts, Value,
};
use ual::{Client, Identity, Kind};

/// Records of User Access Logging databases.
pub const NAMESPACE: Namespace = Namespace::new("windows.ual");

/// The companion file naming the roles.
const IDENTITY: &str = "SystemIdentity.mdb";
/// An ESE database's signature, at offset 4 of its header.
const ESE_SIGNATURE: [u8; 4] = [0xef, 0xcd, 0xab, 0x89];

/// One record per client, role, name resolution, virtual machine and
/// server identity.
#[derive(Debug, Default, Clone, Copy)]
pub struct UalAdapter;

impl Adapter for UalAdapter {
    fn parser(&self) -> ParserInfo {
        ParserInfo {
            name: "ual",
            version: ual::VERSION,
        }
    }

    fn namespaces(&self) -> &'static [Namespace] {
        &[NAMESPACE]
    }

    /// By name (`Current.mdb`, `{GUID}.mdb`, `SystemIdentity.mdb`) and the
    /// ESE signature.
    fn probe(&self, name: &str, head: &[u8]) -> Confidence {
        if ual::detect(name).is_some() && head.get(4..8) == Some(&ESE_SIGNATURE[..]) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }

    fn companions(&self, name: &str) -> Vec<String> {
        match ual::detect(name) {
            Some(Kind::Year) => vec![IDENTITY.to_owned()],
            _ => Vec::new(),
        }
    }

    fn parse(&self, input: &Input<'_>, sink: &mut dyn Sink) -> Result<(), ParseError> {
        self.parse_with_companions(input, &[], sink)
    }

    fn parse_with_companions(
        &self,
        input: &Input<'_>,
        companions: &[Companion<'_>],
        sink: &mut dyn Sink,
    ) -> Result<(), ParseError> {
        let fail = |e: ual::Error| ParseError::at(0, e.0);
        if ual::detect(input.name) == Some(Kind::Identity) {
            let identity = ual::read_identity(input.data).map_err(fail)?;
            report(sink, &identity.problems);
            for (row, system) in (0u64..).zip(&identity.systems) {
                let mut record = self.record(input, "SYSTEM_IDENTITY", row);
                push_time(
                    &mut record,
                    TimeKind::Created,
                    "CreationTime",
                    system.created,
                );
                let mut fields = Fields::new();
                text(&mut fields, "HostName", system.host_name.as_deref());
                text(&mut fields, "Domain", system.domain.as_deref());
                text(&mut fields, "OsVersion", system.os_version.as_deref());
                text(&mut fields, "Manufacturer", system.manufacturer.as_deref());
                text(&mut fields, "Product", system.product.as_deref());
                text(&mut fields, "Serial", system.serial.as_deref());
                record.fields = fields;
                record.facets.host_name.clone_from(&system.host_name);
                record.summary = format!(
                    "UAL server identity: {} ({}), Windows {}",
                    system.host_name.as_deref().unwrap_or("?"),
                    system.domain.as_deref().unwrap_or("?"),
                    system.os_version.as_deref().unwrap_or("?")
                );
                sink.record(record);
            }
            return Ok(());
        }
        let identity = companions
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(IDENTITY))
            .and_then(|c| ual::read_identity(c.data).ok())
            .unwrap_or_default();
        let year = ual::read_year(input.data).map_err(fail)?;
        report(sink, &year.problems);
        for (row, client) in (0u64..).zip(&year.clients) {
            sink.record(self.client(input, row, client, &identity));
        }
        for (row, role) in (0u64..).zip(&year.roles) {
            let mut record = self.record(input, "ROLE_ACCESS", row);
            push_time(
                &mut record,
                TimeKind::FirstSeen,
                "FirstSeen",
                role.first_seen,
            );
            push_time(&mut record, TimeKind::LastSeen, "LastSeen", role.last_seen);
            let name = identity.role_name(&role.role);
            let mut fields = Fields::new();
            text(&mut fields, "Role", Some(&role.role));
            text(&mut fields, "RoleName", name);
            record.fields = fields;
            record.summary = format!("UAL role used: {}", name.unwrap_or(&role.role));
            sink.record(record);
        }
        for (row, resolution) in (0u64..).zip(&year.resolutions) {
            let mut record = self.record(input, "DNS", row);
            push_time(
                &mut record,
                TimeKind::LastSeen,
                "LastSeen",
                resolution.last_seen,
            );
            let mut fields = Fields::new();
            text(&mut fields, "Address", Some(&resolution.address));
            text(&mut fields, "HostName", Some(&resolution.host));
            record.fields = fields;
            record.facets.source_ip = Some(resolution.address.clone()).filter(|a| !a.is_empty());
            record.summary = format!("UAL name: {} is {}", resolution.address, resolution.host);
            sink.record(record);
        }
        for (row, machine) in (0u64..).zip(&year.virtual_machines) {
            let mut record = self.record(input, "VIRTUALMACHINES", row);
            push_time(
                &mut record,
                TimeKind::Created,
                "CreationTime",
                machine.created,
            );
            push_time(
                &mut record,
                TimeKind::LastSeen,
                "LastSeenActive",
                machine.last_active,
            );
            let mut fields = Fields::new();
            text(&mut fields, "VmId", machine.id.as_deref());
            text(&mut fields, "BiosId", machine.bios.as_deref());
            text(&mut fields, "Serial", machine.serial.as_deref());
            record.fields = fields;
            record.summary = format!(
                "UAL virtual machine {}",
                machine.id.as_deref().unwrap_or("?")
            );
            sink.record(record);
        }
        Ok(())
    }
}

impl UalAdapter {
    fn record(self, input: &Input<'_>, table: &str, row: u64) -> Record {
        Record::new(
            input.evidence,
            NAMESPACE,
            Locator::TableRow {
                table: table.to_owned(),
                row,
            },
            self.parser(),
        )
    }

    fn client(self, input: &Input<'_>, row: u64, client: &Client, identity: &Identity) -> Record {
        let mut record = self.record(input, "CLIENTS", row);
        push_time(
            &mut record,
            TimeKind::FirstSeen,
            "InsertDate",
            client.first_access,
        );
        push_time(
            &mut record,
            TimeKind::LastSeen,
            "LastAccess",
            client.last_access,
        );
        let role = identity.role_name(&client.role);
        let days = access_days(client);
        let mut fields = Fields::new();
        text(&mut fields, "Role", Some(&client.role));
        text(&mut fields, "RoleName", role);
        text(&mut fields, "Account", client.user.as_deref());
        text(&mut fields, "Address", client.address.as_deref());
        text(&mut fields, "Tenant", client.tenant.as_deref());
        text(&mut fields, "ClientName", client.client_name.as_deref());
        text(&mut fields, "Days", Some(&days.join("; ")));
        fields.insert(
            "TotalAccesses".into(),
            Value::UInt(u64::from(client.total_accesses)),
        );
        record.fields = fields;
        record.facets = Facets {
            user_name: client.user.clone(),
            source_ip: client.address.clone(),
            ..Facets::default()
        };
        record.summary = format!(
            "UAL: {} from {} used {} {} times ({} days)",
            client.user.as_deref().unwrap_or("?"),
            client.address.as_deref().unwrap_or("?"),
            role.unwrap_or(&client.role),
            client.total_accesses,
            client.days.len()
        );
        record
    }
}

/// The days a client used the role, as dates with their counts
/// (`2022-07-16: 12`): day numbers counted from 1 January of the year of
/// its last access.
fn access_days(client: &Client) -> Vec<String> {
    let Some(year) = client
        .last_access
        .or(client.first_access)
        .and_then(|t| t.to_iso8601())
        .and_then(|iso| iso.get(..4)?.parse::<i64>().ok())
    else {
        return client
            .days
            .iter()
            .map(|(day, count)| format!("day {day}: {count}"))
            .collect();
    };
    let january_first = days_from_civil(year, 1, 1);
    client
        .days
        .iter()
        .map(|&(day, count)| {
            let (y, m, d) = civil_from_days(january_first + i64::from(day) - 1);
            format!("{y:04}-{m:02}-{d:02}: {count}")
        })
        .collect()
}

fn push_time(record: &mut Record, kind: TimeKind, name: &str, time: Option<Ts>) {
    if let Some(time) = time {
        record.times.push(RecordTime::new(kind, name, time));
    }
}

fn report(sink: &mut dyn Sink, problems: &[String]) {
    for reason in problems {
        sink.skipped(Skipped {
            locator: Locator::ByteOffset(0),
            reason: reason.clone(),
        });
    }
}

fn text(fields: &mut Fields, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        fields.insert(name.into(), Value::from(value));
    }
}
