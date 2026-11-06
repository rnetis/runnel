//! SCTP transport (advanced carrier) — Linux only, behind the `sctp`
//! feature flag. Uses a one-to-many style SOCK_SEQPACKET socket so each
//! `send` is one SCTP message and each `recv` returns exactly one message:
//! message boundaries come from SCTP, not from a length prefix.
//!
//! Reliability and congestion control are SCTP-native; unordered delivery
//! can be requested per-message via PPID/flags once negotiated. SCTP
//! availability across NATs and providers is inconsistent — treat this as
//! an optional carrier, never a dependency of the architecture.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use async_trait::async_trait;
use tokio::io::unix::AsyncFd;

use crate::traits::{Transport, TransportError, TransportKind};

pub struct SctpTransport {
    fd: AsyncFd<i32>,
    peer: std::sync::Mutex<Option<SocketAddr>>,
    local: SocketAddr,
}

impl SctpTransport {
    /// Create an unconnected SCTP seqpacket socket bound to `local`.
    pub fn bind(local: SocketAddr) -> io::Result<Self> {
        let domain = if local.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        unsafe {
            let fd = libc::socket(domain, libc::SOCK_SEQPACKET, libc::IPPROTO_SCTP);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // Non-blocking for AsyncFd integration.
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            let (addr, len) = to_sockaddr(&local);
            if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, len) < 0 {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }
            let sock = SctpTransport {
                fd: AsyncFd::new(fd)?,
                peer: std::sync::Mutex::new(None),
                local: local,
            };
            Ok(sock)
        }
    }

    /// Associate with the remote endpoint.
    pub fn connect_to(&self, peer: SocketAddr) -> io::Result<()> {
        unsafe {
            let (addr, len) = to_sockaddr(&peer);
            // sctp_connectx would support multihoming; single-address v0.1.
            let rc = libc::connect(
                self.fd.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                len,
            );
            if rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock {
                return Err(io::Error::last_os_error());
            }
        }
        *self.peer.lock().unwrap() = Some(peer);
        Ok(())
    }

    fn raw(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}

fn to_sockaddr(addr: &SocketAddr) -> (libc::sockaddr_storage, u32) {
    match addr {
        SocketAddr::V4(v4) => {
            let a = libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            let mut s: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
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
            let mut s: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            unsafe { std::ptr::copy_nonoverlapping(&a, &mut s as *mut _ as *mut _, 1) };
            (s, std::mem::size_of::<libc::sockaddr_in6>() as u32)
        }
    }
}

#[async_trait]
impl Transport for SctpTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Sctp
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        *self.peer.lock().unwrap()
    }

    async fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
        let peer = self
            .peer
            .lock()
            .unwrap()
            .ok_or(TransportError::NoPeer)?
            ;
        loop {
            let mut guard = self.fd.writable().await?;
            // Build the msghdr after the await point: raw pointers must not
            // be held across .await (futures must remain Send).
            let (mut name, namelen) = to_sockaddr(&peer);
            let mut iov = libc::iovec {
                iov_base: frame.as_ptr() as *mut _,
                iov_len: frame.len(),
            };
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_name = &mut name as *mut _ as *mut libc::c_void;
            hdr.msg_namelen = namelen;
            hdr.msg_iov = &mut iov;
            hdr.msg_iovlen = 1;
            let rc = unsafe { libc::sendmsg(self.raw(), &hdr, libc::MSG_DONTWAIT) };
            match rc {
                n if n >= 0 => {
                    guard.clear_ready();
                    return Ok(());
                }
                _ if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    continue;
                }
                _ => return Err(io::Error::last_os_error().into()),
            }
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        loop {
            let mut guard = self.fd.readable().await?;
            // Build after the await point (Send futures).
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            let mut from: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_name = &mut from as *mut _ as *mut libc::c_void;
            hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
            hdr.msg_iov = &mut iov;
            hdr.msg_iovlen = 1;
            let rc = unsafe { libc::recvmsg(self.raw(), &mut hdr, libc::MSG_DONTWAIT) };
            match rc {
                n if n >= 0 => {
                    guard.clear_ready();
                    if hdr.msg_flags & libc::MSG_TRUNC != 0 {
                        return Err(TransportError::FrameTooLarge {
                            size: buf.len(),
                            max: buf.len(),
                        });
                    }
                    return Ok(n as usize);
                }
                _ if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    continue;
                }
                _ => return Err(io::Error::last_os_error().into()),
            }
        }
    }

    async fn close(&self) -> Result<(), TransportError> {
        unsafe {
            libc::close(self.raw());
        }
        Ok(())
    }
}
