//! The two bounded resources between connections and the output thread (design §14.1):
//! a counting semaphore for parse/match jobs, and an output queue bounded by items and bytes.
//! Both wait with a deadline, so a stalled consumer turns into a 503, never into memory.

use crate::output::Event;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Instant;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panicking holder can't leave these counters half-updated in a way that matters more
    // than stalling everything would.
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Waits on `cv` until `ready` or the deadline. Returns whether `ready` held.
fn wait_until<'a, T>(
    cv: &Condvar,
    mut g: MutexGuard<'a, T>,
    deadline: Instant,
    ready: impl Fn(&T) -> bool,
) -> (MutexGuard<'a, T>, bool) {
    while !ready(&g) {
        let now = Instant::now();
        if now >= deadline {
            return (g, false);
        }
        g = cv
            .wait_timeout(g, deadline - now)
            .unwrap_or_else(|p| p.into_inner())
            .0;
    }
    (g, true)
}

pub struct Semaphore {
    free: Mutex<usize>,
    cv: Condvar,
}

pub struct JobPermit(Arc<Semaphore>);

impl Semaphore {
    pub fn new(n: usize) -> Arc<Semaphore> {
        Arc::new(Semaphore {
            free: Mutex::new(n),
            cv: Condvar::new(),
        })
    }

    pub fn acquire(self: &Arc<Self>, deadline: Instant) -> Option<JobPermit> {
        let (mut g, ok) = wait_until(&self.cv, lock(&self.free), deadline, |n| *n > 0);
        if !ok {
            return None;
        }
        *g -= 1;
        Some(JobPermit(Arc::clone(self)))
    }
}

impl Drop for JobPermit {
    fn drop(&mut self) {
        *lock(&self.0.free) += 1;
        self.0.cv.notify_one();
    }
}

struct State {
    items: VecDeque<Event>,
    /// Bytes of queued events plus bytes reserved by permits not yet used.
    bytes: usize,
    /// Slots (count) taken by queued events plus outstanding permits.
    slots: usize,
    closed: bool,
}

pub struct Queue {
    state: Mutex<State>,
    not_full: Condvar,
    not_empty: Condvar,
    max_items: usize,
    max_bytes: usize,
}

/// Capacity set aside for one event; sending it can't block or fail for lack of room.
pub struct Permit<'q> {
    queue: &'q Queue,
    bytes: usize,
    used: bool,
}

impl Queue {
    pub fn new(max_items: usize, max_bytes: usize) -> Arc<Queue> {
        Arc::new(Queue {
            state: Mutex::new(State {
                items: VecDeque::new(),
                bytes: 0,
                slots: 0,
                closed: false,
            }),
            not_full: Condvar::new(),
            not_empty: Condvar::new(),
            max_items,
            max_bytes,
        })
    }

    /// Reserves room for an event of `bytes`. A single event over the byte cap is allowed
    /// alone, so an oversized one waits for an empty queue instead of never fitting.
    pub fn reserve(&self, bytes: usize, deadline: Instant) -> Option<Permit<'_>> {
        let bytes = bytes.min(self.max_bytes);
        let (mut g, ok) = wait_until(&self.not_full, lock(&self.state), deadline, |s| {
            s.closed || (s.slots < self.max_items && s.bytes + bytes <= self.max_bytes)
        });
        if !ok || g.closed {
            return None;
        }
        g.slots += 1;
        g.bytes += bytes;
        Some(Permit {
            queue: self,
            bytes,
            used: false,
        })
    }

    /// Blocks for the next event; `None` once closed and drained.
    pub fn pop(&self) -> Option<Event> {
        let mut g = lock(&self.state);
        loop {
            if let Some(ev) = g.items.pop_front() {
                g.slots -= 1;
                g.bytes -= ev.reserved_bytes(self.max_bytes);
                self.not_full.notify_all();
                return Some(ev);
            }
            if g.closed {
                return None;
            }
            g = self.not_empty.wait(g).unwrap_or_else(|p| p.into_inner());
        }
    }

    pub fn close(&self) {
        lock(&self.state).closed = true;
        self.not_empty.notify_all();
        self.not_full.notify_all();
    }
}

impl Permit<'_> {
    pub fn send(mut self, ev: Event) {
        self.used = true;
        debug_assert_eq!(ev.reserved_bytes(self.queue.max_bytes), self.bytes);
        let mut g = lock(&self.queue.state);
        g.items.push_back(ev);
        self.queue.not_empty.notify_one();
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if !self.used {
            let mut g = lock(&self.queue.state);
            g.slots -= 1;
            g.bytes -= self.bytes;
            self.queue.not_full.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn soon(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }

    fn ev(n: usize) -> Event {
        Event::sized_for_test(n)
    }

    #[test]
    fn semaphore_limits_and_releases() {
        let s = Semaphore::new(2);
        let a = s.acquire(soon(50)).unwrap();
        let _b = s.acquire(soon(50)).unwrap();
        assert!(s.acquire(soon(30)).is_none());
        drop(a);
        assert!(s.acquire(soon(50)).is_some());
    }

    #[test]
    fn queue_is_bounded_by_count_and_bytes() {
        let q = Queue::new(2, 100);
        let p1 = q.reserve(40, soon(50)).unwrap();
        let p2 = q.reserve(40, soon(50)).unwrap();
        assert!(q.reserve(1, soon(30)).is_none(), "count cap");
        p1.send(ev(40));
        drop(p2);
        let p3 = q.reserve(60, soon(50)).unwrap();
        assert!(q.reserve(10, soon(30)).is_none(), "byte cap");
        p3.send(ev(60));
        assert!(q.pop().is_some());
        assert!(q.reserve(40, soon(50)).is_some());
    }

    #[test]
    fn oversized_event_waits_for_an_empty_queue() {
        let q = Queue::new(4, 100);
        let p = q.reserve(10_000, soon(50)).unwrap();
        assert!(q.reserve(1, soon(30)).is_none());
        drop(p);
        assert!(q.reserve(1, soon(50)).is_some());
    }

    #[test]
    fn close_wakes_everyone() {
        let q = Queue::new(1, 100);
        q.close();
        assert!(q.pop().is_none());
        assert!(q.reserve(1, soon(50)).is_none());
    }
}
