//! TUN device trait and an in-process loopback device for testing.

use async_trait::async_trait;
use tokio::sync::mpsc;

use rnl_core::Result;

/// The only OS-facing packet interface the RNL engine knows about.
#[async_trait]
pub trait TunDevice: Send + Sync {
    /// Read one IP packet that the OS (or test harness) wants tunneled.
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
    /// Deliver one decrypted IP packet to the OS (or test harness).
    async fn send(&self, pkt: &[u8]) -> Result<()>;
    /// Effective virtual MTU.
    fn mtu(&self) -> u16 {
        1380
    }
}

/// In-process device: `send()` loops packets back so `recv()` returns them.
/// Lets a client and server binary run a full encrypted tunnel on one host
/// with no privileges. Packets are consumed in FIFO order.
pub struct LoopbackDevice {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
}

impl LoopbackDevice {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            tx,
            rx: tokio::sync::Mutex::new(rx),
        }
    }
}

impl Default for LoopbackDevice {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TunDevice for LoopbackDevice {
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let pkt = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(rnl_core::Error::Closed)?;
        let n = pkt.len().min(buf.len());
        buf[..n].copy_from_slice(&pkt[..n]);
        Ok(n)
    }

    async fn send(&self, pkt: &[u8]) -> Result<()> {
        let _ = self.tx.send(pkt.to_vec());
        Ok(())
    }
}
