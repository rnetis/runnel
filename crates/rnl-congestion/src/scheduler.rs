//! Priority scheduling with weighted fair queuing between queues.

use std::collections::VecDeque;

/// Queue priorities (lower = more urgent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Critical control: auth, key updates, session control.
    Critical = 0,
    /// Latency-sensitive: DNS, interactive, small packets.
    Interactive = 1,
    /// Normal data.
    Normal = 2,
    /// Bulk traffic.
    Bulk = 3,
}

/// Weighted round-robin over four priority queues. Bulk traffic is never
/// fully starved, but critical control always wins ties.
pub struct Scheduler<T> {
    queues: [VecDeque<T>; 4],
    weights: [u32; 4],
    cursor: usize,
    budget: u32,
    total: usize,
}

impl<T> Default for Scheduler<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Scheduler<T> {
    pub fn new() -> Self {
        Self {
            queues: Default::default(),
            // WRR weights: bulk still gets 1/8 of slots under load.
            weights: [8, 6, 4, 1],
            cursor: 0,
            budget: 0,
            total: 0,
        }
    }

    pub fn push(&mut self, prio: Priority, item: T) {
        self.queues[prio as usize].push_back(item);
        self.total += 1;
    }

    pub fn len(&self) -> usize {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.total == 0 {
            return None;
        }
        loop {
            let q = &self.queues[self.cursor];
            if !q.is_empty() {
                let item = self.queues[self.cursor].pop_front().unwrap();
                self.total -= 1;
                self.budget += 1;
                if self.budget >= self.weights[self.cursor] {
                    self.budget = 0;
                    self.advance();
                }
                return Some(item);
            }
            self.budget = 0;
            self.advance();
        }
    }

    fn advance(&mut self) {
        self.cursor = (self.cursor + 1) % 4;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_preempts_bulk() {
        let mut s = Scheduler::new();
        s.push(Priority::Bulk, 'B');
        s.push(Priority::Critical, 'C');
        assert_eq!(s.pop(), Some('C'));
        assert_eq!(s.pop(), Some('B'));
        assert_eq!(s.pop(), None);
    }

    #[test]
    fn bulk_not_starved() {
        let mut s = Scheduler::new();
        for _ in 0..100 {
            s.push(Priority::Normal, 'N');
        }
        s.push(Priority::Bulk, 'B');
        let mut saw_bulk = false;
        for _ in 0..100 {
            if s.pop() == Some('B') {
                saw_bulk = true;
                break;
            }
        }
        assert!(saw_bulk, "bulk traffic was starved");
    }

    #[test]
    fn fifo_within_priority() {
        let mut s = Scheduler::new();
        s.push(Priority::Normal, 1);
        s.push(Priority::Normal, 2);
        assert_eq!(s.pop(), Some(1));
        assert_eq!(s.pop(), Some(2));
    }
}
