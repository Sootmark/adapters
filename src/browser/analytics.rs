//! Google Analytics' cookies (`__utma`, `__utmb`, `__utmt`, `__utmz`),
//! decoded: on its cookie's record, the visits it counts as times and the
//! visitor, session and referral as fields.

use browser::GoogleAnalytics;
use model::{Fields, Record, TimeKind};

use super::extras::push;
use super::{number, text};
use crate::key::field_name;

/// The time of the visit a cookie last counted.
const LAST_VISIT: &str = "AnalyticsLastVisit";

/// The `__utmz` variables with names of their own, and those names.
const VARIABLES: [(&str, &str); 5] = [
    ("utmcsr", "AnalyticsSource"),
    ("utmccn", "AnalyticsCampaign"),
    ("utmcmd", "AnalyticsMedium"),
    ("utmctr", "AnalyticsTerm"),
    ("utmcct", "AnalyticsContent"),
];

/// Add what `analytics` says to its cookie's record and fields.
pub(super) fn describe(record: &mut Record, fields: &mut Fields, analytics: &GoogleAnalytics) {
    text(fields, "AnalyticsCookie", Some(cookie_name(analytics)));
    match analytics {
        GoogleAnalytics::Utma {
            domain_hash,
            visitor_id,
            first_visit,
            previous_visit,
            last_visit,
            sessions,
        } => {
            for (kind, name, time) in [
                (TimeKind::FirstSeen, "AnalyticsFirstVisit", first_visit),
                (TimeKind::Other, "AnalyticsPreviousVisit", previous_visit),
                (TimeKind::LastSeen, LAST_VISIT, last_visit),
            ] {
                push(record, kind, name, *time);
            }
            text(fields, "AnalyticsDomainHash", domain_hash.as_deref());
            text(fields, "AnalyticsVisitorId", visitor_id.as_deref());
            number(fields, "AnalyticsSessions", *sessions);
        }
        GoogleAnalytics::Utmb {
            domain_hash,
            pages_viewed,
            last_visit,
        } => {
            push(record, TimeKind::LastSeen, LAST_VISIT, *last_visit);
            text(fields, "AnalyticsDomainHash", domain_hash.as_deref());
            number(fields, "AnalyticsPagesViewed", *pages_viewed);
        }
        GoogleAnalytics::Utmt { last_visit } => {
            push(record, TimeKind::LastSeen, LAST_VISIT, *last_visit);
        }
        GoogleAnalytics::Utmz {
            domain_hash,
            last_visit,
            sessions,
            sources,
            variables,
        } => {
            push(record, TimeKind::LastSeen, LAST_VISIT, *last_visit);
            text(fields, "AnalyticsDomainHash", domain_hash.as_deref());
            number(fields, "AnalyticsSessions", *sessions);
            number(fields, "AnalyticsSources", *sources);
            for (key, value) in variables {
                let name = VARIABLES
                    .iter()
                    .find(|(known, _)| known == key)
                    .map_or_else(
                        || field_name(&format!("Analytics_{key}")),
                        |(_, name)| (*name).to_owned(),
                    );
                text(fields, &name, Some(value));
            }
        }
    }
}

/// What `analytics` says, in a few words: `visitor, 12 sessions`.
pub(super) fn summary(analytics: &GoogleAnalytics) -> String {
    match analytics {
        GoogleAnalytics::Utma { sessions, .. } => match sessions {
            Some(sessions) => format!("Google Analytics visitor, {sessions} sessions"),
            None => "Google Analytics visitor".to_owned(),
        },
        GoogleAnalytics::Utmb { pages_viewed, .. } => match pages_viewed {
            Some(pages) => format!("Google Analytics session, {pages} pages viewed"),
            None => "Google Analytics session".to_owned(),
        },
        GoogleAnalytics::Utmt { .. } => "Google Analytics throttle".to_owned(),
        GoogleAnalytics::Utmz { variables, .. } => {
            let variable = |key: &str| {
                variables
                    .iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.as_str())
            };
            let source = variable("utmcsr").map_or_else(String::new, |s| format!(" from {s}"));
            let term =
                variable("utmctr").map_or_else(String::new, |t| format!(", searched for {t}"));
            format!("Google Analytics referral{source}{term}")
        }
    }
}

fn cookie_name(analytics: &GoogleAnalytics) -> &'static str {
    match analytics {
        GoogleAnalytics::Utma { .. } => "utma",
        GoogleAnalytics::Utmb { .. } => "utmb",
        GoogleAnalytics::Utmt { .. } => "utmt",
        GoogleAnalytics::Utmz { .. } => "utmz",
    }
}
