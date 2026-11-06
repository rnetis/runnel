//! NewReno-style congestion controller with pacing.

use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct NewReno {
    /// Congestion window in bytes.
    cwnd: f64,
    ssthresh: f64,
    bytes_in_flight: u64,
    srtt: Option<Duration>,
    rttvar: Duration,
    /// Bytes acked since last loss event (Reno fast recovery bookkeeping).
    acked_since_recovery: u64,
    recovery_start: Option<Instant>,
    latest_loss_rate: f64,
    min_cwnd: f64,
    max_cwnd: f64,
}

impl NewReno {
    pub fn new(initial_cwnd_packets: u64, mtu: u16) -> Self {
        let init = (initial_cwnd_packets as f64) * (mtu as f64);
        Self {
            cwnd: init,
            ssthresh: init * 2.0,
            bytes_in_flight: 0,
            srtt: None,
            rttvar: Duration::ZERO,
            acked_since_recovery: 0,
            recovery_start: None,
            latest_loss_rate: 0.0,
            min_cwnd: 2.0 * (mtu as f64),
            max_cwnd: 64.0 * 1024.0 * 1024.0,
        }
    }

    pub fn cwnd(&self) -> u64 {
        self.cwnd as u64
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    pub fn latest_loss_rate(&self) -> f64 {
        self.latest_loss_rate
    }

    pub fn on_packet_sent(&mut self, bytes: usize) {
        self.bytes_in_flight += bytes as u64;
    }

    /// Feedback from an ACK: `bytes_acked` newly-acknowledged bytes.
    pub fn on_ack(&mut self, bytes_acked: usize, rtt_sample: Option<Duration>, now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_acked as u64);

        if let Some(rtt) = rtt_sample {
            match self.srtt {
                None => {
                    self.srtt = Some(rtt);
                    self.rttvar = rtt / 2;
                }
                Some(s) => {
                    self.rttvar = self.rttvar.mul_f64(0.75)
                        + rtt.abs_diff(s).mul_f64(0.25);
                    self.srtt = Some(s.mul_f64(0.875) + rtt.mul_f64(0.125));
                }
            }
        }

        let in_recovery = self
            .recovery_start
            .map(|t| now.duration_since(t) < self.srtt().unwrap_or(Duration::from_millis(100)))
            .unwrap_or(false);

        if !in_recovery {
            if self.cwnd < self.ssthresh {
                self.cwnd += bytes_acked as f64; // slow start
            } else {
                // congestion avoidance: ~1 MTU per RTT
                let rtt = self.srtt.unwrap_or(Duration::from_millis(100)).as_secs_f64();
                let mtu = 1380.0;
                self.cwnd += (bytes_acked as f64) * mtu / self.cwnd.max(1.0) * rtt.max(0.001);
            }
        }
        self.acked_since_recovery += bytes_acked as u64;
        self.clamp();
    }

    /// Loss detected (timeout-style, e.g. no ACKs for > RTO).
    pub fn on_loss(&mut self, now: Instant) {
        self.ssthresh = (self.cwnd / 2.0).max(self.min_cwnd);
        self.cwnd = self.ssthresh;
        self.recovery_start = Some(now);
        self.acked_since_recovery = 0;
        self.clamp();
    }

    pub fn on_loss_sample(&mut self, rate: f64) {
        self.latest_loss_rate = rate;
    }

    /// Pacing rate in bytes/sec (RFC 8033-ish: cwnd / SRTT, min 1 MTU/50ms).
    pub fn pacing_rate(&self) -> u64 {
        let rtt = self
            .srtt
            .unwrap_or(Duration::from_millis(50))
            .as_secs_f64()
            .max(0.001);
        ((self.cwnd / rtt) as u64).max(1380 * 20)
    }

    /// Whether a send of `bytes` fits the window right now.
    pub fn can_send(&self) -> bool {
        (self.bytes_in_flight as f64) < self.cwnd
    }

    /// Delay before the next send if the window is full.
    pub fn send_delay(&self) -> Duration {
        if self.can_send() {
            return Duration::ZERO;
        }
        let rate = self.pacing_rate() as f64;
        Duration::from_secs_f64((self.bytes_in_flight as f64 - self.cwnd) / rate)
    }

    fn clamp(&mut self) {
        self.cwnd = self.cwnd.clamp(self.min_cwnd, self.max_cwnd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_start_grows() {
        let mut c = NewReno::new(10, 1380);
        let now = Instant::now();
        let before = c.cwnd();
        c.on_packet_sent(1380);
        c.on_ack(1380, Some(Duration::from_millis(20)), now);
        assert!(c.cwnd() > before);
    }

    #[test]
    fn loss_halves() {
        let mut c = NewReno::new(100, 1380);
        for _ in 0..50 {
            c.on_ack(1380, Some(Duration::from_millis(10)), Instant::now());
        }
        let big = c.cwnd();
        c.on_loss(Instant::now());
        assert!(c.cwnd() <= big / 2 + 1);
        assert!(c.cwnd() >= 2 * 1380);
    }

    #[test]
    fn inflight_accounting() {
        let mut c = NewReno::new(10, 1380);
        c.on_packet_sent(1000);
        assert_eq!(c.bytes_in_flight(), 1000);
        c.on_ack(400, None, Instant::now());
        assert_eq!(c.bytes_in_flight(), 600);
    }
}
