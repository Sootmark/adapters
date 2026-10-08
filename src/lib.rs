//! One adapter per parser dependency.
//!
//! Parsers are independent libraries that know nothing about Sootmark. Each
//! module here wraps one of them and maps its output into [`model::Record`]s,
//! keeping the promises of [`model::adapter`].

pub mod applogs;
pub mod audit;
pub mod avlogs;
pub mod bits;
pub mod bodyfile;
pub mod browser;
pub mod bsm;
pub mod cloudlogs;
pub mod cloudsync;
pub mod containers;
mod csv;
pub mod defender;
pub mod esxi;
pub mod eventtranscript;
pub mod evt;
pub mod evtx;
pub mod ez;
pub mod filehistory;
pub mod fwlogs;
pub mod hayabusa;
pub mod history;
mod home;
pub mod indx;
pub mod journal;
pub mod jumplist;
mod key;
pub mod live;
pub mod lnk;
pub mod macos;
pub mod messengers;
pub mod mft;
pub mod mlocate;
pub mod mplog;
pub mod msiecf;
pub mod notifications;
pub mod ntfslog;
pub mod office;
pub mod onedrive;
pub mod packages;
pub mod pe;
pub mod persistence;
pub mod plaso;
pub mod prefetch;
pub mod printing;
pub mod recyclebin;
pub mod registry;
pub mod search;
pub mod spotlight;
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
