//! Decides which notifying changes are due, without a CLI, a clock or a notifier (macos.md
//! §2.7). A new notifying id waits `confirm_delay` and is posted only if a scan that *started*
//! after that still sees it, so a file caught mid-rewrite can't fire and then vanish.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct ChangeTracker {
    /// How long a new id waits before it may be posted.
    pub confirm_delay: Duration,
    /// Id → the time after which a scan may confirm it.
    candidates: HashMap<String, Instant>,
    /// Id → its confirm time, for a post still in flight.
    posting: HashMap<String, Instant>,
    /// Bumped whenever the baseline is replaced; a post from an older epoch is dropped whole.
    epoch: u64,
    /// The notifying ids of the latest scan observed: the only ones a post may record.
    latest: HashSet<String>,
}

impl Default for ChangeTracker {
    fn default() -> Self {
        Self::new(Duration::from_secs(30))
    }
}

impl ChangeTracker {
    pub fn new(confirm_delay: Duration) -> Self {
        Self {
            confirm_delay,
            candidates: HashMap::new(),
            posting: HashMap::new(),
            epoch: 0,
            latest: HashSet::new(),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn is_candidate(&self, id: &str) -> bool {
        self.candidates.contains_key(id)
    }

    pub fn is_posting(&self, id: &str) -> bool {
        self.posting.contains_key(id)
    }

    pub fn posting_is_empty(&self) -> bool {
        self.posting.is_empty()
    }

    /// The notifying ids of the latest scan observed.
    pub fn latest(&self) -> &HashSet<String> {
        &self.latest
    }

    /// Steps 3–5, for a scan that started at `started` and saw `notifying` (in core order).
    /// Trims `notified` to what is still present, then returns the ids due now: still present,
    /// not notified, not being posted, and past their confirm time. They move to `posting`.
    pub fn observe(
        &mut self,
        notifying: &[String],
        notified: &mut HashSet<String>,
        started: Instant,
    ) -> Vec<String> {
        let present: HashSet<String> = notifying.iter().cloned().collect();
        notified.retain(|id| present.contains(id));
        let fresh: HashSet<&String> = present
            .iter()
            .filter(|id| !notified.contains(*id) && !self.posting.contains_key(*id))
            .collect();
        self.candidates.retain(|id, _| fresh.contains(id));
        for id in notifying {
            if fresh.contains(id) && !self.candidates.contains_key(id) {
                self.candidates
                    .insert(id.clone(), started + self.confirm_delay);
            }
        }
        let due: Vec<String> = notifying
            .iter()
            .filter(|id| self.candidates.get(*id).is_some_and(|t| *t <= started))
            .cloned()
            .collect();
        for id in &due {
            if let Some(t) = self.candidates.remove(id) {
                self.posting.insert(id.clone(), t);
            }
        }
        self.latest = present;
        due
    }

    /// The bookkeeping after a post (step 6) that was started in `epoch`. A post from an older
    /// epoch changes nothing, so it can't erase a newer reservation. Otherwise it records the
    /// handled ids that the latest scan still sees; the unhandled ones stay due.
    pub fn finish_post(
        &mut self,
        due: &[String],
        handled: &HashSet<String>,
        epoch: u64,
        notified: &mut HashSet<String>,
    ) {
        if epoch != self.epoch {
            return;
        }
        for id in due {
            let confirm_after = self.posting.remove(id);
            if !self.latest.contains(id) {
                continue;
            }
            if handled.contains(id) {
                notified.insert(id.clone());
            } else if let Some(t) = confirm_after {
                self.candidates.insert(id.clone(), t);
            }
        }
    }

    /// The earliest time a scan could confirm something, if anything is waiting.
    pub fn next_confirm(&self) -> Option<Instant> {
        self.candidates.values().min().copied()
    }

    /// Forgets everything in memory (the baseline was replaced) and starts a new epoch.
    pub fn reset(&mut self) {
        self.candidates.clear();
        self.posting.clear();
        self.latest.clear();
        self.epoch += 1;
    }
}
