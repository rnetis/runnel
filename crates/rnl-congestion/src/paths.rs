//! Path state and active/standby scheduling (multipath groundwork).
//!
//! v0.1 policy per the design doc: validate a path before it carries data,
//! keep exactly ONE active path, and hold validated standbys for instant
//! failover. Packet-level multipath distribution comes later; this module is
//! the decision layer both the client and server engines will share.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::controller::NewReno;

#[derive(Debug)]
pub struct NetworkPath {
    pub id: u32,
    pub remote: SocketAddr,
    pub mtu: u16,
    pub rtt: Duration,
    pub loss_rate: f64,
    pub congestion: NewReno,
    /// Only validated paths may carry data (anti-hijack requirement).
    pub validated: bool,
    pub last_seen: Instant,
}

#[derive(Debug)]
pub struct PathManager {
    paths: Vec<NetworkPath>,
    active_id: Option<u32>,
    next_id: u32,
    /// How stale a path may be before it is considered gone.
    path_timeout: Duration,
}

impl PathManager {
    pub fn new() -> Self {
        Self {
            paths: Vec::new(),
            active_id: None,
            next_id: 1,
            path_timeout: Duration::from_secs(60),
        }
    }

    /// Register a path; returns its id. Unvalidated until proven.
    pub fn add_path(&mut self, remote: SocketAddr, mtu: u16, now: Instant) -> u32 {
        if let Some(p) = self.paths.iter_mut().find(|p| p.remote == remote) {
            p.last_seen = now;
            return p.id;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.paths.push(NetworkPath {
            id,
            remote,
            mtu,
            rtt: Duration::from_millis(50),
            loss_rate: 0.0,
            congestion: NewReno::new(10, mtu),
            validated: false,
            last_seen: now,
        });
        id
    }

    pub fn get(&self, id: u32) -> Option<&NetworkPath> {
        self.paths.iter().find(|p| p.id == id)
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut NetworkPath> {
        self.paths.iter_mut().find(|p| p.id == id)
    }

    pub fn mark_validated(&mut self, id: u32, now: Instant) {
        if let Some(p) = self.paths.iter_mut().find(|p| p.id == id) {
            p.validated = true;
            p.last_seen = now;
        }
    }

    /// The path currently carrying data. Active/standby policy: exactly one.
    pub fn active(&self) -> Option<&NetworkPath> {
        self.active_id.and_then(|id| self.get(id))
    }

    pub fn active_id(&self) -> Option<u32> {
        self.active_id
    }

    /// Activate a path (only validated ones are eligible).
    pub fn activate(&mut self, id: u32, now: Instant) -> bool {
        let eligible = self.get(id).map(|p| p.validated).unwrap_or(false);
        if eligible {
            self.active_id = Some(id);
            if let Some(p) = self.get_mut(id) {
                p.last_seen = now;
            }
        }
        eligible
    }

    /// Choose the best validated standby to promote: lowest loss, then RTT.
    fn best_standby(&self) -> Option<u32> {
        self.paths
            .iter()
            .filter(|p| p.validated && Some(p.id) != self.active_id)
            .min_by(|a, b| {
                a.loss_rate
                    .partial_cmp(&b.loss_rate)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(a.rtt.cmp(&b.rtt))
            })
            .map(|p| p.id)
    }

    /// Called when the active path degrades (loss spike / timeout).
    /// Promotes the best validated standby if one exists; returns the new
    /// active id. Active/standby means we switch, never split.
    pub fn degrade_active(&mut self, now: Instant) -> Option<u32> {
        let old = self.active_id;
        if let Some(id) = old {
            if let Some(p) = self.get_mut(id) {
                p.congestion.on_loss(now);
                p.loss_rate = (p.loss_rate + 0.1).min(1.0);
            }
        }
        if let Some(next) = self.best_standby() {
            self.active_id = Some(next);
            if let Some(p) = self.get_mut(next) {
                p.last_seen = now;
            }
            return Some(next);
        }
        // No standby: stay on the degraded path (it still gets congestion
        // window halving) rather than blackholing.
        old
    }

    /// Feedback from the active path's ACKs.
    pub fn on_active_ack(&mut self, bytes: usize, rtt: Option<Duration>, now: Instant) {
        if let Some(id) = self.active_id {
            if let Some(p) = self.get_mut(id) {
                p.congestion.on_ack(bytes, rtt, now);
                if let Some(r) = rtt {
                    p.rtt = r;
                }
                p.loss_rate *= 0.95;
                p.last_seen = now;
            }
        }
    }

    /// Paths that have gone silent past the timeout are forgotten.
    pub fn reap(&mut self, now: Instant) {
        self.paths
            .retain(|p| now.duration_since(p.last_seen) < self.path_timeout);
        if let Some(id) = self.active_id {
            if self.get(id).is_none() {
                self.active_id = None;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

impl Default for PathManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Instant {
        Instant::now()
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn unvalidated_paths_never_activate() {
        let mut pm = PathManager::new();
        let id = pm.add_path(addr(1000), 1380, now());
        assert!(!pm.activate(id, now()));
        assert!(pm.active().is_none());
        pm.mark_validated(id, now());
        assert!(pm.activate(id, now()));
        assert_eq!(pm.active().unwrap().id, id);
    }

    #[test]
    fn active_standby_failover() {
        let mut pm = PathManager::new();
        let a = pm.add_path(addr(1001), 1380, now());
        let b = pm.add_path(addr(1002), 1380, now());
        pm.mark_validated(a, now());
        pm.mark_validated(b, now());
        pm.activate(a, now());
        assert_eq!(pm.active_id(), Some(a));

        // Degradation promotes a validated standby, never splits traffic.
        let new_active = pm.degrade_active(now()).expect("standby available");
        assert_eq!(new_active, b);
        assert_eq!(pm.active_id(), Some(b));
    }

    #[test]
    fn degrade_without_standby_keeps_active() {
        let mut pm = PathManager::new();
        let a = pm.add_path(addr(1003), 1380, now());
        pm.mark_validated(a, now());
        pm.activate(a, now());
        assert_eq!(pm.degrade_active(now()), Some(a));
        assert_eq!(pm.active_id(), Some(a));
    }

    #[test]
    fn best_standby_prefers_low_loss_then_rtt() {
        let mut pm = PathManager::new();
        let a = pm.add_path(addr(1004), 1380, now());
        let b = pm.add_path(addr(1005), 1380, now());
        let c = pm.add_path(addr(1006), 1380, now());
        for id in [a, b, c] {
            pm.mark_validated(id, now());
        }
        pm.activate(a, now());
        // b has loss, c is clean and faster.
        pm.get_mut(b).unwrap().loss_rate = 0.3;
        pm.get_mut(c).unwrap().rtt = Duration::from_millis(10);
        let promoted = pm.degrade_active(now()).unwrap();
        assert_eq!(promoted, c);
    }

    #[test]
    fn ack_feedback_updates_path() {
        let mut pm = PathManager::new();
        let a = pm.add_path(addr(1007), 1380, now());
        pm.mark_validated(a, now());
        pm.activate(a, now());
        pm.on_active_ack(1340, Some(Duration::from_millis(7)), now());
        assert_eq!(pm.active().unwrap().rtt, Duration::from_millis(7));
    }

    #[test]
    fn reap_drops_stale_paths() {
        let mut pm = PathManager::new();
        let a = pm.add_path(addr(1008), 1380, now());
        pm.mark_validated(a, now());
        pm.activate(a, now());
        pm.reap(now() + Duration::from_secs(3600));
        assert!(pm.is_empty());
        assert!(pm.active_id().is_none());
    }
}
