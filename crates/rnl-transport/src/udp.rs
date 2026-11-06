//! UDP transport: primary data path. One datagram per encrypted frame,
//! socket buffers tuned for throughput, pinned peer, and (on Linux)
//! `recvmmsg`/`sendmmsg` batching to amortize syscall cost.

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::traits::{Transport, TransportError, TransportKind};

pub struct UdpTransport {
    sock: UdpSocket,
    /// None until the peer is pinned (server sockets) or provided (client).
    peer: Mutex<Option<SocketAddr>>,
}

/// Upper bound on datagrams per batch call.
pub const MAX_BATCH: usize = 64;

impl UdpTransport {
    /// Bind an ephemeral local port, unconnected; the peer is learned from
    /// (or pinned to) `peer` on first use.
    pub async fn connect(peer: SocketAddr) -> std::io::Result<Self> {
        let local: SocketAddr = if peer.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        Self::bind(local, Some(peer)).await
    }

    pub async fn bind(local: SocketAddr, peer: Option<SocketAddr>) -> std::io::Result<Self> {
        Self::bind_sharded(local, peer, false).await
    }

    /// Bind with optional SO_REUSEPORT for multi-worker receive sharding.
    /// All workers on the same address must pass the same `reuse_port`.
    pub async fn bind_sharded(
        local: SocketAddr,
        peer: Option<SocketAddr>,
        reuse_port: bool,
    ) -> std::io::Result<Self> {
        let socket = Socket::new(Domain::for_address(local), Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        #[cfg(all(unix, not(target_os = "solaris"), feature = "reuseport"))]
        if reuse_port {
            socket.set_reuse_port(true)?;
        }
        #[cfg(all(unix, not(feature = "reuseport")))]
        let _ = reuse_port;
        #[cfg(not(windows))]
        {
            let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
            let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
        }
        socket.bind(&local.into())?;
        let sock = UdpSocket::from_std(socket.into())?;
        Ok(Self {
            sock,
            peer: Mutex::new(peer),
        })
    }

    /// Create a new transport with a fresh local (ephemeral) port to the
    /// same peer — the primitive behind NAT rebind / migration probes.
    pub async fn rebind(&self) -> std::io::Result<Self> {
        let peer = self.remote_addr();
        let local: SocketAddr = if peer.map(|p| p.is_ipv4()).unwrap_or(true) {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        Self::bind(local, peer).await
    }

    pub fn set_peer(&self, peer: SocketAddr) {
        *self.peer.lock().unwrap() = Some(peer);
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.sock
    }

    /// Receive up to `bufs.len()` datagrams in as few syscalls as possible.
    /// Non-blocking after a readability wait: returns 0 when drained.
    /// Non-Linux platforms fall back to a `recv_from` loop.
    pub async fn recv_batch(
        &self,
        bufs: &mut [&mut [u8]],
        sizes: &mut [usize],
        addrs: &mut [Option<SocketAddr>],
    ) -> Result<usize, TransportError> {
        let n = bufs.len().min(sizes.len()).min(addrs.len());
        if n == 0 {
            return Ok(0);
        }
        // Wait for at least one datagram, then drain without blocking.
        if sizes.iter().all(|&s| s == 0) {
            self.sock.readable().await?;
        }
        #[cfg(target_os = "linux")]
        {
            match self.try_recv_batch_linux(bufs, sizes, addrs, n) {
                Ok(k) if k > 0 => return Ok(k),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(0),
                Err(e) => return Err(e.into()),
            }
            // Fallback: poll-style drain via recv_from for the remainder.
            Ok(self.drain_with_recv_from(bufs, sizes, addrs, n).await)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(self.drain_with_recv_from(bufs, sizes, addrs, n).await)
        }
    }

    #[cfg(not(target_os = "linux"))]
    async fn drain_with_recv_from(
        &self,
        bufs: &mut [&mut [u8]],
        sizes: &mut [usize],
        addrs: &mut [Option<SocketAddr>],
        n: usize,
    ) -> usize {
        let mut got = 0;
        for i in 0..n {
            match self.sock.try_recv_from(&mut bufs[i][..]) {
                Ok((len, from)) => {
                    sizes[i] = len;
                    addrs[i] = Some(from);
                    got += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        got
    }

    #[cfg(target_os = "linux")]
    async fn drain_with_recv_from(
        &self,
        bufs: &mut [&mut [u8]],
        sizes: &mut [usize],
        addrs: &mut [Option<SocketAddr>],
        n: usize,
    ) -> usize {
        let mut got = 0;
        for i in 0..n {
            match self.sock.try_recv_from(&mut bufs[i][..]) {
                Ok((len, from)) => {
                    sizes[i] = len;
                    addrs[i] = Some(from);
                    got += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        got
    }

    #[cfg(target_os = "linux")]
    fn try_recv_batch_linux(
        &self,
        bufs: &mut [&mut [u8]],
        sizes: &mut [usize],
        addrs: &mut [Option<SocketAddr>],
        n: usize,
    ) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        let mut iovecs: Vec<libc::iovec> = bufs[..n]
            .iter_mut()
            .map(|b| libc::iovec {
                iov_base: (**b).as_mut_ptr().cast(),
                iov_len: (**b).len(),
            })
            .collect();
        let mut storage: Vec<libc::sockaddr_storage> =
            vec![unsafe { std::mem::zeroed() }; n];
        let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(n);
        for i in 0..n {
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_name = &mut storage[i] as *mut _ as *mut _;
            hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
            hdr.msg_iov = &mut iovecs[i];
            hdr.msg_iovlen = 1;
            msgs.push(libc::mmsghdr {
                msg_hdr: hdr,
                msg_len: 0,
            });
        }
        let r = unsafe {
            libc::recvmmsg(
                self.sock.as_raw_fd(),
                msgs.as_mut_ptr(),
                n as u32,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        let r = r as usize;
        for i in 0..r {
            sizes[i] = msgs[i].msg_len as usize;
            let from = storage_to_addr(&storage[i]);
            addrs[i] = Some(from);
            // Pin the peer on first datagram (server-side sockets start unset).
            let mut peer = self.peer.lock().unwrap();
            match *peer {
                Some(expected) if expected != from => {
                    tracing::debug!(%from, %expected, "datagram from unexpected source");
                }
                _ => *peer = Some(from),
            }
        }
        Ok(r)
    }

    /// Send multiple frames to the pinned peer, ideally in one `sendmmsg`.
    /// Returns the number of frames queued.
    pub async fn send_batch(&self, frames: &[&[u8]]) -> Result<usize, TransportError> {
        let peer = self
            .peer
            .lock()
            .unwrap()
            .ok_or(TransportError::NoPeer)?;
        self.send_batch_to(peer, frames).await
    }

    /// Batch-send to an explicit address (per-datagram replies on the
    /// server, including path-validation challenges to new addresses).
    pub async fn send_batch_to(
        &self,
        peer: SocketAddr,
        frames: &[&[u8]],
    ) -> Result<usize, TransportError> {
        #[cfg(target_os = "linux")]
        {
            if frames.len() > 1 {
                self.sock.writable().await?;
                match self.try_send_batch_linux(frames, peer) {
                    Ok(k) => return Ok(k),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        let mut sent = 0;
        for f in frames {
            match self.sock.send_to(f, peer).await {
                Ok(_) => sent += 1,
                Err(_e) if sent > 0 => break, // partial batch is acceptable
                Err(e) => return Err(e.into()),
            }
        }
        Ok(sent)
    }
}

#[cfg(target_os = "linux")]
fn storage_to_addr(s: &libc::sockaddr_storage) -> SocketAddr {
    match s.ss_family as i32 {
        libc::AF_INET => {
            let a: &libc::sockaddr_in =
                unsafe { &*(s as *const _ as *const libc::sockaddr_in) };
            SocketAddr::from((
                std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
                u16::from_be(a.sin_port),
            ))
        }
        libc::AF_INET6 => {
            let a: &libc::sockaddr_in6 =
                unsafe { &*(s as *const _ as *const libc::sockaddr_in6) };
            SocketAddr::from((
                std::net::Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
            ))
        }
        _ => SocketAddr::from(([0, 0, 0, 0], 0)),
    }
}

#[cfg(target_os = "linux")]
impl UdpTransport {
    fn try_send_batch_linux(
        &self,
        frames: &[&[u8]],
        peer: SocketAddr,
    ) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        let n = frames.len().min(MAX_BATCH);
        let mut iovecs: Vec<libc::iovec> = frames[..n]
            .iter()
            .map(|f| libc::iovec {
                iov_base: f.as_ptr() as *mut _,
                iov_len: f.len(),
            })
            .collect();
        let (mut name, namelen) = addr_to_storage(peer);
        let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(n);
        for i in 0..n {
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_name = &mut name as *mut _ as *mut libc::c_void;
            hdr.msg_namelen = namelen;
            // Each message carries exactly its own iovec — sharing the whole
            // array would concatenate every frame into every datagram.
            hdr.msg_iov = &mut iovecs[i];
            hdr.msg_iovlen = 1;
            msgs.push(libc::mmsghdr {
                msg_hdr: hdr,
                msg_len: 0,
            });
        }
        let r = unsafe {
            libc::sendmmsg(
                self.sock.as_raw_fd(),
                msgs.as_mut_ptr(),
                n as u32,
                libc::MSG_DONTWAIT,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(r as usize)
    }
}

#[cfg(target_os = "linux")]
fn addr_to_storage(peer: SocketAddr) -> (libc::sockaddr_storage, u32) {
    let mut s: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match peer {
        SocketAddr::V4(v4) => {
            let a = libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe { std::ptr::copy_nonoverlapping(&a, &mut s as *mut _ as *mut _, 1) };
            (s, std::mem::size_of::<libc::sockaddr_in>() as u32)
        }
        SocketAddr::V6(v6) => {
            let a = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as _,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe { std::ptr::copy_nonoverlapping(&a, &mut s as *mut _ as *mut _, 1) };
            (s, std::mem::size_of::<libc::sockaddr_in6>() as u32)
        }
    }
}

#[async_trait]
impl Transport for UdpTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Udp
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        *self.peer.lock().unwrap()
    }

    async fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
        let peer = self
            .peer
            .lock()
            .unwrap()
            .ok_or(TransportError::NoPeer)?;
        self.sock.send_to(frame, peer).await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let (n, from) = self.sock.recv_from(buf).await?;
        {
            let mut peer = self.peer.lock().unwrap();
            // Pin the peer on first datagram; flag spoofed sources after.
            match *peer {
                Some(expected) if from != expected => {
                    tracing::debug!(%from, %expected, "datagram from unexpected source");
                }
                _ => *peer = Some(from),
            }
        }
        Ok(n)
    }

    async fn close(&self) -> Result<(), TransportError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn batch_recv_delivers_all_datagrams() {
        let a = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), None).await.unwrap();
        let b_peer = a.local_addr().unwrap();
        let b = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        a.set_peer(b_peer);
        let frames: Vec<Vec<u8>> = (0..8u32).map(|i| i.to_be_bytes().repeat(10)).collect();
        let refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
        let sent = a.send_batch(&refs).await.unwrap();
        assert_eq!(sent, 8);

        let mut bufs_raw: Vec<Vec<u8>> = vec![vec![0u8; 2048]; 16];
        let mut bufs: Vec<&mut [u8]> = bufs_raw.iter_mut().map(|b| b.as_mut_slice()).collect();
        let mut sizes = vec![0usize; 16];
        let mut addrs: Vec<Option<SocketAddr>> = vec![None; 16];
        let mut got = 0;
        for _ in 0..10 {
            let k = b.recv_batch(&mut bufs, &mut sizes, &mut addrs).await.unwrap();
            got += k;
            if got == 8 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(got, 8, "batch recv must deliver all datagrams");
    }
}
