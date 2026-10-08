//! One adapter per parser dependency.
//!
//! Parsers are independent libraries that know nothing about Sootmark. Each
//! module here wraps one of them and maps its output into [`model::Record`]s,
//! keeping the promises of [`model::adapter`].

pub mod audit;
pub mod avlogs;
pub mod bodyfile;
pub mod browser;
pub mod cloudlogs;
pub mod containers;
mod csv;
pub mod defender;
pub mod evtx;
pub mod ez;
pub mod hayabusa;
pub mod history;
mod home;
pub mod journal;
pub mod jumplist;
pub mod live;
pub mod lnk;
pub mod macos;
pub mod mft;
pub mod packages;
pub mod persistence;
pub mod plaso;
pub mod prefetch;
pub mod recyclebin;
pub mod registry;
pub mod search;
pub mod srum;
pub mod syslog;
pub mod tasks;
mod timestamp;
pub mod ual;
pub mod usn;
pub mod utmp;
pub mod velociraptor;
pub mod weblogs;
pub mod winlogs;
pub mod wintimeline;
pub mod wmi;
pub mod xdr;
