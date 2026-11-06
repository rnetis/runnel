//! Datagram Packetization Layer Path MTU Discovery (DPLPMTUD-style, RFC 8899
//! adapted to RNL frames).
//!
//! Probes are full-size PATH_CHALLENGE frames (padded payload) that the peer
//! echoes as PATH_RESPONSE. A confirmed probe raises the confirmed datagram
//! size; a probe timeout lowers it to the last confirmed value. Effective
//! payload capacity for IP data = confirmed - HEADER_LEN - TAG_LEN.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::packet::{frame, TAG_LEN, HEADER_LEN};

pub const BASE_MTU: u16 = 1200; // IPv6 minimum reassembly size

#[derive(Debug)]
pub struct Probe {
    pub size: u16,
    pub token: [u8; 8],
    pub sent: Instant,
    pub timeout: Duration,
}

#[derive(Debug)]
pub struct MtuDiscovery {
    base: u16,
    max: u16,
    /// Largest confirmed full RNL datagram size (header + payload + tag).
    confirmed: u16,
    outstanding: Option<Probe>,
    next_probe_at: Instant,
    probe_interval: Duration,
    /// Sizes still to try (descending decisions happen on confirm/timeout).
    pending: VecDeque<u16>,
    pub probes_sent: u64,
    pub probes_confirmed: u64,
    pub probes_failed: u64,
}

impl MtuDiscovery {
    pub fn new(max_datagram: u16) -> Self {
        let base = BASE_MTU.min(max_datagram);
        let mut pending = VecDeque::new();
        // Candidate ladder: base -> typical underlay sizes -> max.
        for cand in [1380u16, 1452, 1472, 1500] {
            let c = cand.min(max_datagram);
            if c > base && !pending.contains(&c) {
                pending.push_back(c);
            }
        }
        Self {
            base,
            max: max_datagram,
            confirmed: base,
            outstanding: None,
            next_probe_at: Instant::now(),
            probe_interval: Duration::from_secs(30),
            pending,
            probes_sent: 0,
            probes_confirmed: 0,
            probes_failed: 0,
        }
    }

    /// Payload capacity for data frames at the confirmed datagram size.
    pub fn payload_capacity(&self) -> u16 {
        self.confirmed.saturating_sub((HEADER_LEN + TAG_LEN) as u16)
    }

    pub fn confirmed(&self) -> u16 {
        self.confirmed
    }

    /// If a probe is due, returns the probe token; the caller seals a
    /// PATH_CHALLENGE frame padded so the full datagram is `size` bytes.
    pub fn maybe_probe(&mut self, now: Instant) -> Option<Probe> {
        if self.outstanding.is_some() || now < self.next_probe_at {
            return None;
        }
        let size = match self.pending.pop_front() {
            Some(s) if s > self.confirmed => s,
            _ => return None,
        };
        let token = rand_token();
        self.outstanding = Some(Probe {
            size,
            token,
            sent: now,
            timeout: Duration::from_secs(3),
        });
        self.probes_sent += 1;
        Some(Probe {
            size,
            token,
            sent: now,
            timeout: Duration::from_secs(3),
        })
    }

    /// PATH_RESPONSE with matching token confirms that datagram size.
    pub fn on_response(&mut self, token: &[u8], size: u16, now: Instant) -> bool {
        let Some(p) = &self.outstanding else {
            return false;
        };
        if token != &p.token {
            return false;
        }
        if size >= self.confirmed {
            self.confirmed = size;
            self.probes_confirmed += 1;
        }
        self.outstanding = None;
        self.next_probe_at = now + self.probe_interval;
        true
    }

    /// Called periodically; fails an outstanding probe on timeout.
    pub fn tick(&mut self, now: Instant) {
        if let Some(p) = self.outstanding.take() {
            if now.duration_since(p.sent) > p.timeout {
                // Do not retry this size; keep last confirmed.
                self.probes_failed += 1;
                self.pending.retain(|&s| s <= self.confirmed);
                self.next_probe_at = now + self.probe_interval * 4;
            } else {
                self.outstanding = Some(p);
            }
        }
    }

    pub fn is_probing(&self) -> bool {
        self.outstanding.is_some()
    }

    /// Datagrams of this size are safe to send right now.
    pub fn can_send_size(&self, total: usize) -> bool {
        (total as u16) <= self.confirmed || self.confirmed == self.max
    }

    pub fn base(&self) -> u16 {
        self.base
    }
}

fn rand_token() -> [u8; 8] {
    use rand::RngCore;
    let mut t = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut t);
    t
}

/// Total datagram size for a probe of the given payload length.
pub fn probe_datagram_size(payload_len: usize) -> u16 {
    (HEADER_LEN + payload_len + TAG_LEN) as u16
}

/// Build a PATH_CHALLENGE payload: token + zero padding to reach the
/// requested payload length.
pub fn probe_payload(token: [u8; 8], payload_len: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(payload_len);
    p.extend_from_slice(&token);
    p.resize(payload_len.max(8), 0);
    p
}

pub fn is_path_challenge(t: u8) -> bool {
    t == frame::PATH_CHALLENGE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_ascending_and_confirms() {
        let mut d = MtuDiscovery::new(1500);
        let now = Instant::now();
        assert_eq!(d.confirmed(), 1200);
        assert_eq!(d.payload_capacity(), 1200 - 40);

        let p = d.maybe_probe(now).expect("first probe due");
        assert_eq!(p.size, 1380);
        assert!(d.is_probing());
        assert!(d.maybe_probe(now).is_none(), "no parallel probes");

        assert!(d.on_response(&p.token, 1380, now));
        assert_eq!(d.confirmed(), 1380);
        assert_eq!(d.payload_capacity(), 1380 - 40);
    }

    #[test]
    fn timeout_lowers_expectations() {
        let mut d = MtuDiscovery::new(1500);
        let now = Instant::now();
        let p = d.maybe_probe(now).unwrap();
        // No response; tick past timeout.
        d.tick(now + Duration::from_secs(4));
        assert!(!d.is_probing());
        assert_eq!(d.confirmed(), 1200, "confirmed unchanged on timeout");
        assert!(d.probes_failed == 1);
        // Next probe skips the failed size.
        let later = now + Duration::from_secs(30 * 4);
        let p2 = d.maybe_probe(later);
        if let Some(p2) = p2 {
            assert!(p2.size > 1380 || p2.size <= 1200, "skipped failed size");
        }
        let _ = p;
    }

    #[test]
    fn wrong_token_ignored() {
        let mut d = MtuDiscovery::new(1500);
        let now = Instant::now();
        let p = d.maybe_probe(now).unwrap();
        assert!(!d.on_response(&[0u8; 8], 1380, now));
        assert!(d.is_probing());
        assert!(d.on_response(&p.token, 1380, now));
    }

    #[test]
    fn capped_at_max() {
        let mut d = MtuDiscovery::new(1452);
        let now = Instant::now();
        let mut confirmed_any = false;
        for _ in 0..8 {
            if let Some(p) = d.maybe_probe(now) {
                d.on_response(&p.token, p.size, now);
                confirmed_any = true;
            } else {
                // advance time past cooldown
                let _ = d.maybe_probe(now + Duration::from_secs(120));
            }
        }
        assert!(confirmed_any);
        assert!(d.confirmed() <= 1452);
    }
}
