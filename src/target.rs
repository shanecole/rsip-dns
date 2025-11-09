use rsip::{Port, Transport};
use std::net::{IpAddr, SocketAddr};

/// The (ip, port, transport, ttl) tuple resolved that should be used as the next peer target.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Target {
    pub ip_addr: IpAddr,
    pub port: Port,
    pub transport: Transport,
    pub ttl: u32,
}

impl Target {
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::from((self.ip_addr, self.port.into()))
    }
}

impl From<(IpAddr, Port, Transport)> for Target {
    fn from(from: (IpAddr, Port, Transport)) -> Target {
        let (ip_addr, port, transport) = from;

        Target { ip_addr, port, transport, ttl: 300 }
    }
}

impl From<(IpAddr, Port, Transport, u32)> for Target {
    fn from(from: (IpAddr, Port, Transport, u32)) -> Target {
        let (ip_addr, port, transport, ttl) = from;

        Target { ip_addr, port, transport, ttl }
    }
}
