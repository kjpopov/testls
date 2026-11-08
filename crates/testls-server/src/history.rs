//! In-memory scan history, bounded in size, that wakes progress streams
//! whenever a scan moves on.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

use serde::Serialize;
use testls_report::sarif;
use tokio::sync::watch;

/// Where a scan stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    /// Still probing the server.
    Running,
    /// Finished with a report.
    Done,
    /// Stopped without a report.
    Failed,
}

/// One finished section of a scan as sent to clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Section {
    /// Section name, such as `ciphers`.
    #[serde(rename = "section")]
    pub name: &'static str,
    /// Protocol version for per-version sections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The section as plain text, the same as the CLI prints.
    pub text: String,
}

/// What a finished scan leaves for report downloads.
#[derive(Debug, Clone)]
pub(crate) struct Finished {
    /// The JSON report.
    pub json: String,
    /// Findings and grade as plain text, printed after the sections.
    pub tail: String,
    /// Grade and triaged findings for the summary formats.
    pub summary: sarif::Scan,
}

/// One scan in the history.
#[derive(Debug)]
pub(crate) struct Record {
    /// Server-assigned id.
    pub id: u64,
    /// Target as `host:port`.
    pub target: String,
    /// Unix time the scan was requested.
    pub created_at: i64,
    /// Where the scan stands.
    pub status: Status,
    /// Target, address and SNI as plain text, printed before the sections.
    pub header: String,
    /// Sections finished so far, in scan order.
    pub sections: Vec<Section>,
    /// Report data once the scan is done.
    pub finished: Option<Finished>,
    /// Why the scan failed.
    pub error: Option<String>,
    /// Bumped on every change so progress streams wake up.
    changed: watch::Sender<()>,
}

impl Record {
    /// Wakes every progress stream watching this record.
    fn touch(&self) {
        self.changed.send_replace(());
    }
}

/// Scan history holding at most `capacity` records; the oldest finished
/// record makes room for a new one.
#[derive(Debug)]
pub(crate) struct History {
    /// Records oldest first, plus the next id.
    inner: Mutex<(VecDeque<Record>, u64)>,
    /// Most records to keep.
    capacity: usize,
}

impl History {
    /// An empty history keeping at most `capacity` records.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new((VecDeque::new(), 1)),
            capacity: capacity.max(1),
        }
    }

    /// Locks the history. A panic while holding the lock leaves the data
    /// consistent, so a poisoned lock is still usable.
    pub fn lock(&self) -> MutexGuard<'_, (VecDeque<Record>, u64)> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Adds a running scan and returns its id, or `None` when every kept
    /// record is still running.
    pub fn insert(&self, target: String, header: String, created_at: i64) -> Option<u64> {
        let mut guard = self.lock();
        let (records, next_id) = &mut *guard;
        if records.len() >= self.capacity {
            let oldest = records.iter().position(|r| r.status != Status::Running)?;
            records.remove(oldest);
        }
        let id = *next_id;
        *next_id += 1;
        records.push_back(Record {
            id,
            target,
            created_at,
            status: Status::Running,
            header,
            sections: Vec::new(),
            finished: None,
            error: None,
            changed: watch::channel(()).0,
        });
        Some(id)
    }

    /// Runs `f` on the record with `id`, if it is still kept.
    pub fn with<T>(&self, id: u64, f: impl FnOnce(&mut Record) -> T) -> Option<T> {
        self.lock().0.iter_mut().find(|r| r.id == id).map(f)
    }

    /// Subscribes to changes of the record with `id`.
    pub fn subscribe(&self, id: u64) -> Option<watch::Receiver<()>> {
        self.with(id, |r| r.changed.subscribe())
    }

    /// Appends a finished section to a running scan.
    pub fn push(&self, id: u64, section: Section) {
        self.with(id, |r| {
            r.sections.push(section);
            r.touch();
        });
    }

    /// Marks a scan done with its report data.
    pub fn finish(&self, id: u64, finished: Finished) {
        self.with(id, |r| {
            r.status = Status::Done;
            r.finished = Some(finished);
            r.touch();
        });
    }

    /// Marks a scan failed with the reason.
    pub fn fail(&self, id: u64, error: String) {
        self.with(id, |r| {
            r.status = Status::Failed;
            r.error = Some(error);
            r.touch();
        });
    }

    /// Marks a scan failed with the reason if it is still running.
    pub fn abort(&self, id: u64, error: String) {
        self.with(id, |r| {
            if r.status == Status::Running {
                r.status = Status::Failed;
                r.error = Some(error);
                r.touch();
            }
        });
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the scan history.

    use super::*;

    /// A plain section for tests.
    fn section(text: &str) -> Section {
        Section {
            name: "protocols",
            version: None,
            text: text.to_owned(),
        }
    }

    /// The oldest finished record makes room; running ones are kept.
    #[test]
    fn bounded() {
        let history = History::new(2);
        let first = history.insert("a:443".into(), String::new(), 0).unwrap();
        let second = history.insert("b:443".into(), String::new(), 0).unwrap();
        assert_eq!(history.insert("c:443".into(), String::new(), 0), None);
        history.fail(second, "boom".into());
        let third = history.insert("c:443".into(), String::new(), 0).unwrap();
        let ids: Vec<u64> = history.lock().0.iter().map(|r| r.id).collect();
        assert_eq!(ids, [first, third]);
    }

    /// Changes wake subscribers and land on the record.
    #[test]
    fn updates() {
        let history = History::new(4);
        let id = history.insert("a:443".into(), String::new(), 0).unwrap();
        let mut rx = history.subscribe(id).unwrap();
        rx.mark_unchanged();
        history.push(id, section("one"));
        assert!(rx.has_changed().unwrap());
        history.fail(id, "boom".into());
        let (status, sections, error) = history
            .with(id, |r| (r.status, r.sections.clone(), r.error.clone()))
            .unwrap();
        assert_eq!(status, Status::Failed);
        assert_eq!(sections, [section("one")]);
        assert_eq!(error.as_deref(), Some("boom"));
        assert!(history.subscribe(99).is_none());
    }

    /// Aborting fails a running scan and leaves an ended one alone.
    #[test]
    fn aborts() {
        let history = History::new(4);
        let running = history.insert("a:443".into(), String::new(), 0).unwrap();
        let ended = history.insert("b:443".into(), String::new(), 0).unwrap();
        history.fail(ended, "boom".into());
        history.abort(running, "gone".into());
        history.abort(ended, "gone".into());
        let state = |id| history.with(id, |r| (r.status, r.error.clone())).unwrap();
        assert_eq!(state(running), (Status::Failed, Some("gone".into())));
        assert_eq!(state(ended), (Status::Failed, Some("boom".into())));
    }
}
