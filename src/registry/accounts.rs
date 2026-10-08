//! SAM: the machine's local accounts (one record each: created, last logon,
//! password set, last failed logon, flags, counts) and its local groups'
//! members (one record per membership: who is an administrator).

use common::time::Ts;
use model::{Facets, RecordTime, TimeKind, Value};
use registry::sam::{self, Group, User};
use registry::Hive;

use super::{Out, SAM_GROUPS, SAM_USERS};

impl Out<'_, '_> {
    /// The local accounts and groups' members.
    pub(super) fn accounts(&mut self, hive: &Hive<'_>) {
        let users = sam::users(hive);
        self.problems(users.problems);
        for user in &users.entries {
            self.user(user);
        }
        let groups = sam::groups(hive);
        self.problems(groups.problems);
        for group in &groups.entries {
            self.memberships(group);
        }
    }

    fn user(&mut self, user: &User) {
        let mut record = self.keyed(SAM_USERS, &user.key, Some("F"), user.key_last_written);
        for (time, kind, name) in [
            (user.created, TimeKind::Created, "Created"),
            (user.last_logon, TimeKind::LastSeen, "LastLogon"),
            (
                user.password_last_set,
                TimeKind::Modified,
                "PasswordLastSet",
            ),
            (user.last_failed_logon, TimeKind::Other, "LastFailedLogon"),
        ] {
            if let Some(time) = time {
                record
                    .times
                    .push(RecordTime::new(kind, name, Ts::from_filetime(time)));
            }
        }
        record.facets = Facets {
            user_name: user.name.clone(),
            ..Facets::default()
        };
        let fields = &mut record.fields;
        fields.insert("Rid".into(), Value::UInt(u64::from(user.rid)));
        for (name, value) in [
            ("Name", &user.name),
            ("FullName", &user.full_name),
            ("Comment", &user.comment),
        ] {
            if let Some(value) = value {
                fields.insert(name.into(), Value::from(value.as_str()));
            }
        }
        fields.insert("Flags".into(), Value::from(format!("{:#x}", user.flags)));
        for (name, value) in [
            ("Disabled", user.disabled()),
            ("PasswordNotRequired", user.password_not_required()),
            ("PasswordNeverExpires", user.password_never_expires()),
            ("Locked", user.locked()),
        ] {
            fields.insert(name.into(), Value::Bool(value));
        }
        fields.insert("Logons".into(), Value::UInt(u64::from(user.logons)));
        fields.insert(
            "FailedLogons".into(),
            Value::UInt(u64::from(user.failed_logons)),
        );
        if let Some(expires) = user.account_expires {
            fields.insert(
                "AccountExpires".into(),
                Value::Time(Ts::from_filetime(expires)),
            );
        }
        let state = if user.disabled() { ", disabled" } else { "" };
        record.summary = format!(
            "Local account {} (RID {}): {} logons{state}",
            user.name.as_deref().unwrap_or("?"),
            user.rid,
            user.logons
        );
        self.sink.record(record);
    }

    fn memberships(&mut self, group: &Group) {
        let name = group.name.as_deref().unwrap_or("?");
        for member in &group.members {
            let mut record = self.keyed(SAM_GROUPS, &group.key, Some("C"), group.key_last_written);
            record.facets = Facets {
                user_sid: Some(member.clone()),
                ..Facets::default()
            };
            let fields = &mut record.fields;
            fields.insert("GroupRid".into(), Value::UInt(u64::from(group.rid)));
            fields.insert("Group".into(), Value::from(name));
            fields.insert("Member".into(), Value::from(member.as_str()));
            record.summary = format!("{member} is a member of {name}");
            self.sink.record(record);
        }
    }
}
