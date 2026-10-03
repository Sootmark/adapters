//! One adapter per parser dependency.
//!
//! Parsers are independent libraries that know nothing about Sootmark. Each
//! module here wraps one of them and maps its output into [`model::Record`]s,
//! keeping the promises of [`model::adapter`].

pub mod audit;
mod csv;
pub mod evtx;
pub mod ez;
pub mod hayabusa;
pub mod history;
pub mod journal;
pub mod jumplist;
pub mod lnk;
pub mod mft;
pub mod plaso;
pub mod prefetch;
pub mod registry;
pub mod syslog;
mod timestamp;
pub mod usn;
pub mod utmp;
pub mod velociraptor;
