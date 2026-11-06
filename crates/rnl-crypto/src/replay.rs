//! Sliding replay window (4096 packets), RFC 6479-style bitmap.

pub const REPLAY_WINDOW: u64 = 4096;

const WORD_BITS: u64 = 64;
const WORDS: usize = (REPLAY_WINDOW / WORD_BITS) as usize;

/// Tracks the highest accepted packet number and a bitmap of the previous
/// `REPLAY_WINDOW` slots. Duplicate or too-old packets are rejected.
#[derive(Debug)]
pub struct SlidingWindow {
    highest: u64,
    seen_any: bool,
    bitmap: [u64; WORDS],
}

impl Default for SlidingWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl SlidingWindow {
    pub fn new() -> Self {
        Self {
            highest: 0,
            seen_any: false,
            bitmap: [0; WORDS],
        }
    }

    /// Returns true if this packet number is fresh; marks it as seen.
    pub fn check_and_update(&mut self, pn: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.highest = pn;
            self.mark(pn);
            return true;
        }
        if pn > self.highest {
            self.shift(pn - self.highest);
            self.highest = pn;
            self.mark(pn);
            return true;
        }
        let age = self.highest - pn;
        if age >= REPLAY_WINDOW {
            return false; // Too old.
        }
        if self.is_set(pn) {
            return false; // Duplicate.
        }
        self.mark(pn);
        true
    }

    /// Bit 0 of the bitmap = `highest`, bit N = `highest - N`.
    fn is_set(&self, pn: u64) -> bool {
        let age = self.highest - pn;
        let word = (age / WORD_BITS) as usize;
        let bit = age % WORD_BITS;
        self.bitmap[word] & (1 << bit) != 0
    }

    fn mark(&mut self, pn: u64) {
        let age = self.highest - pn;
        let word = (age / WORD_BITS) as usize;
        let bit = age % WORD_BITS;
        self.bitmap[word] |= 1 << bit;
    }

    fn shift(&mut self, by: u64) {
        if by >= REPLAY_WINDOW {
            self.bitmap = [0; WORDS];
            return;
        }
        let carry_words = (by / WORD_BITS) as usize;
        let carry_bits = by % WORD_BITS;
        let mut out = [0u64; WORDS];
        for w in 0..WORDS {
            let v = self.bitmap[w];
            let target = w + carry_words;
            if target < WORDS {
                out[target] |= v << carry_bits;
                if carry_bits > 0 && target + 1 < WORDS {
                    out[target + 1] |= v >> (WORD_BITS - carry_bits);
                }
            }
        }
        self.bitmap = out;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order() {
        let mut w = SlidingWindow::new();
        for pn in 0..100 {
            assert!(w.check_and_update(pn), "pn={pn}");
        }
    }

    #[test]
    fn duplicates_rejected() {
        let mut w = SlidingWindow::new();
        assert!(w.check_and_update(5));
        assert!(!w.check_and_update(5));
        assert!(w.check_and_update(6));
    }

    #[test]
    fn reorder_within_window() {
        let mut w = SlidingWindow::new();
        assert!(w.check_and_update(100));
        assert!(w.check_and_update(103));
        assert!(w.check_and_update(101));
        assert!(w.check_and_update(102));
        assert!(!w.check_and_update(103));
    }

    #[test]
    fn too_old_rejected() {
        let mut w = SlidingWindow::new();
        assert!(w.check_and_update(5000));
        assert!(!w.check_and_update(0)); // age 5000 > 4096
        assert!(w.check_and_update(5000 - REPLAY_WINDOW + 1));
    }

    #[test]
    fn window_edges() {
        let mut w = SlidingWindow::new();
        assert!(w.check_and_update(1_000_000));
        assert!(w.check_and_update(1_000_000 - REPLAY_WINDOW + 1)); // oldest in window
        assert!(!w.check_and_update(1_000_000 - REPLAY_WINDOW)); // just outside
    }
}
