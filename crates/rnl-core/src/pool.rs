//! Packet buffer pool: amortizes allocation on the hot data path.

use std::sync::Mutex;

/// Returns buffers to a free list on drop. Buffers are normalized to
/// `buf_size` on acquire.
pub struct BufferPool {
    free: Mutex<Vec<Vec<u8>>>,
    buf_size: usize,
    max_idle: usize,
}

pub struct PooledBuf<'a> {
    buf: Option<Vec<u8>>,
    pool: &'a BufferPool,
}

impl BufferPool {
    pub fn new(buf_size: usize, max_idle: usize) -> Self {
        Self {
            free: Mutex::new(Vec::new()),
            buf_size,
            max_idle,
        }
    }

    pub fn get(&self) -> PooledBuf<'_> {
        let buf = self.free.lock().unwrap().pop().map(|mut b| {
            b.clear();
            b.resize(self.buf_size, 0);
            b
        });
        PooledBuf {
            buf: Some(buf.unwrap_or_else(|| vec![0u8; self.buf_size])),
            pool: self,
        }
    }

    fn put(&self, mut buf: Vec<u8>) {
        buf.clear();
        buf.resize(self.buf_size, 0);
        let mut free = self.free.lock().unwrap();
        if free.len() < self.max_idle {
            free.push(buf);
        }
    }

    pub fn idle(&self) -> usize {
        self.free.lock().unwrap().len()
    }
}

impl<'a> std::ops::Deref for PooledBuf<'a> {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        self.buf.as_ref().unwrap()
    }
}

impl<'a> std::ops::DerefMut for PooledBuf<'a> {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        self.buf.as_mut().unwrap()
    }
}

impl<'a> Drop for PooledBuf<'a> {
    fn drop(&mut self) {
        if let Some(b) = self.buf.take() {
            self.pool.put(b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuse_acquires() {
        let pool = BufferPool::new(1500, 4);
        {
            let mut b = pool.get();
            assert_eq!(b.len(), 1500);
            b[0] = 42;
            b.truncate(10); // shrink; drop path renormalizes
        }
        assert_eq!(pool.idle(), 1);
        {
            let b = pool.get();
            assert_eq!(b.len(), 1500);
            assert_eq!(b[0], 0, "buffer must be zeroed on reuse");
        }
        assert_eq!(pool.idle(), 1);
    }

    #[test]
    fn respects_max_idle() {
        let pool = BufferPool::new(64, 2);
        for _ in 0..10 {
            let _ = pool.get();
        }
        assert!(pool.idle() <= 2);
    }
}
