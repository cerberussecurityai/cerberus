// Bounded per-worker event queue.
//
// proxy-wasm guarantees a single thread per worker, so RefCell is the
// right interior-mutability primitive — no Mutex / atomics needed. The
// only correctness rule: never hold a borrow across an await point. All
// methods on EventQueue release their borrow before returning, so the
// public API is await-safe.
//
// Drop-on-full semantics: when push() encounters a full queue we
// increment a `dropped` counter and return Err(()). The flush loop
// reads the counter via take_dropped() each tick and surfaces it in
// logs (and, in v1.1, will emit it as a synthetic health event in the
// next batch).

use std::cell::RefCell;
use std::collections::VecDeque;

use crate::event::CerberusEvent;

pub struct EventQueue {
    capacity: usize,
    inner: RefCell<Inner>,
}

struct Inner {
    deque: VecDeque<CerberusEvent>,
    dropped: u64,
}

impl EventQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: RefCell::new(Inner {
                // Cap initial alloc at 1024 to avoid eagerly reserving
                // ~10MB on default config (queueCapacity=10_000 ×
                // ~5KB/event); the bound is enforced in push() instead.
                deque: VecDeque::with_capacity(capacity.min(1024)),
                dropped: 0,
            }),
        }
    }

    /// Push an event onto the queue. Returns Err(()) if the queue is
    /// full — caller doesn't need to do anything; the drop is recorded
    /// in the internal counter and surfaced by take_dropped().
    pub fn push(&self, event: CerberusEvent) -> Result<(), ()> {
        let mut inner = self.inner.borrow_mut();
        if inner.deque.len() >= self.capacity {
            inner.dropped += 1;
            return Err(());
        }
        inner.deque.push_back(event);
        Ok(())
    }

    /// Drain up to `max` events. Returns them in arrival order.
    pub fn drain(&self, max: usize) -> Vec<CerberusEvent> {
        let mut inner = self.inner.borrow_mut();
        let n = inner.deque.len().min(max);
        inner.deque.drain(..n).collect()
    }

    /// Reset and return the dropped counter — caller is expected to
    /// surface this via logs/metrics/synthetic events.
    pub fn take_dropped(&self) -> u64 {
        let mut inner = self.inner.borrow_mut();
        let d = inner.dropped;
        inner.dropped = 0;
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn evt(method: &str) -> CerberusEvent {
        CerberusEvent {
            remote_addr: None,
            endpoint: "/x".to_string(),
            scheme: true,
            method: method.to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            headers: Some(BTreeMap::new()),
            query_params: None,
            body: None,
            user_agent: None,
            user_id: None,
        }
    }

    #[test]
    fn push_and_drain() {
        let q = EventQueue::new(10);
        q.push(evt("GET")).unwrap();
        q.push(evt("POST")).unwrap();
        let drained = q.drain(10);
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].method, "GET");
        assert_eq!(drained[1].method, "POST");
    }

    #[test]
    fn drop_when_full() {
        let q = EventQueue::new(2);
        assert!(q.push(evt("A")).is_ok());
        assert!(q.push(evt("B")).is_ok());
        assert!(q.push(evt("C")).is_err());
        assert!(q.push(evt("D")).is_err());
        assert_eq!(q.take_dropped(), 2);
        // Counter resets after read.
        assert_eq!(q.take_dropped(), 0);
    }

    #[test]
    fn drain_capped_at_max() {
        let q = EventQueue::new(10);
        for _ in 0..5 {
            q.push(evt("GET")).unwrap();
        }
        let first = q.drain(2);
        assert_eq!(first.len(), 2);
        let rest = q.drain(10);
        assert_eq!(rest.len(), 3);
    }
}
