//! What the tray remembers between scans (macos.md §2.4): the baseline report the core diffs
//! against (`--since -`) and the change ids already notified. Both live in
//! `$XDG_STATE_HOME/cainary/`, private to the user, since a report lists config paths.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::settings::write_atomic;

const BASELINE: &str = "baseline.json";
const NOTIFIED: &str = "notified.json";

pub struct BaselineStore {
    /// `None` keeps everything in memory (tests, or no state directory).
    dir: Option<PathBuf>,
    baseline: Option<Vec<u8>>,
    notified: HashSet<String>,
}

impl BaselineStore {
    /// The core rejects a larger baseline every time, so there is no point keeping one.
    pub const MAX_BYTES: usize = 1 << 20;

    /// `$XDG_STATE_HOME/cainary`.
    pub fn default_dir() -> Option<PathBuf> {
        crate::state_home().map(|d| d.join("cainary"))
    }

    /// Loads what `dir` holds. Unreadable files count as absent: the next scan rebaselines.
    pub fn open(dir: Option<PathBuf>) -> Self {
        let read = |name: &str| dir.as_ref().and_then(|d| std::fs::read(d.join(name)).ok());
        let baseline = read(BASELINE).filter(|b| b.len() <= Self::MAX_BYTES);
        let notified = read(NOTIFIED)
            .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
            .unwrap_or_default()
            .into_iter()
            .collect();
        Self {
            dir,
            baseline,
            notified,
        }
    }

    /// The last report the user acknowledged, as the core printed it.
    pub fn baseline(&self) -> Option<&[u8]> {
        self.baseline.as_deref()
    }

    /// Change ids already notified or muted.
    pub fn notified(&self) -> &HashSet<String> {
        &self.notified
    }

    pub fn set_notified(&mut self, ids: HashSet<String>) {
        if ids == self.notified {
            return;
        }
        self.notified = ids;
        self.save_notified();
    }

    /// Makes `raw` the baseline and forgets the notified ids (seeding, rebaselining). False,
    /// with the old baseline and ids untouched, when `raw` is too big to keep or can't be saved.
    pub fn replace(&mut self, raw: &[u8]) -> bool {
        if raw.len() > Self::MAX_BYTES {
            return false;
        }
        if let Some(dir) = &self.dir
            && write_atomic(&dir.join(BASELINE), raw, 0o600).is_err()
        {
            return false;
        }
        self.baseline = Some(raw.to_vec());
        self.notified.clear();
        self.save_notified();
        true
    }

    fn save_notified(&self) {
        let Some(dir) = &self.dir else { return };
        let mut ids: Vec<&String> = self.notified.iter().collect();
        ids.sort();
        if let Ok(bytes) = serde_json::to_vec(&ids) {
            // Losing this only means a change may notify once more after a restart.
            let _ = write_atomic(&dir.join(NOTIFIED), &bytes, 0o600);
        }
    }
}
