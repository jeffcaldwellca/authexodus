//! Network interface listing and default LAN address choice (package 2A).
//!
//! The proxy must listen on the address the iPhone or iPad can reach: the Mac's address on the
//! Wi-Fi (or Ethernet) network the two share. A Mac often has several addresses (Wi-Fi,
//! Ethernet, VPN tunnels, Internet Sharing bridges), so the choice is made here, shown to the
//! person with a label, and never defaults to a loopback or tunnel address.
//!
//! `if-addrs` does not expose interface flags, so "up" is approximated by "has an IPv4
//! address" (the system removes addresses from interfaces that are down) and "point to point"
//! by the interface name (`utun`, `ppp`, `ipsec`, ...).
//!
//! Separately from that choice, the proxy is told every address this computer has, on every
//! interface and in both families, so that it refuses to connect to the computer itself on a
//! device's behalf (see [`own_addresses`]).

use std::net::{IpAddr, Ipv4Addr};

/// One address on one interface, as the system reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iface {
    pub name: String,
    pub ip: IpAddr,
}

/// What the session needs to know about this computer's network.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Network {
    /// The addresses the person may choose for the proxy.
    pub candidates: Vec<Candidate>,
    /// Every address on every interface: never a destination for a device's traffic.
    pub own: Vec<IpAddr>,
}

/// An address the person may choose for the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub ip: Ipv4Addr,
    pub label: String,
}

/// Interface name prefixes that are tunnels or point-to-point links (VPNs, Private Relay,
/// cellular modems) or never carry a phone's traffic.
const TUNNEL_PREFIXES: &[&str] = &[
    "utun", "ppp", "ipsec", "tun", "tap", "gif", "stf", "wg", "awdl", "llw", "anpi", "ap",
];

fn is_tunnel(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    TUNNEL_PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// What the person would call this interface. On a Mac `en0` is the Wi-Fi on laptops (the
/// common case); other `en` interfaces are wired adapters.
fn label_for(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let kind = if lower.starts_with("wl") || lower == "en0" {
        "Wi-Fi"
    } else if lower.starts_with("en") || lower.starts_with("eth") {
        "Ethernet"
    } else if lower.starts_with("bridge") {
        "Internet Sharing"
    } else {
        return name.to_string();
    };
    format!("{kind} ({name})")
}

/// The addresses worth offering: IPv4, not loopback, not link-local, not on a tunnel.
/// Order is the system's order.
pub fn candidates(ifaces: &[Iface]) -> Vec<Candidate> {
    ifaces
        .iter()
        .filter_map(|i| match i.ip {
            IpAddr::V4(ip) => Some((i, ip)),
            IpAddr::V6(_) => None,
        })
        .filter(|(_, ip)| !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified())
        .filter(|(i, _)| !is_tunnel(&i.name))
        .map(|(i, ip)| Candidate {
            ip,
            label: label_for(&i.name),
        })
        .collect()
}

/// Every address this computer has: IPv4 and IPv6, on every interface, tunnels and loopback
/// included. Nothing is filtered, because the point is to leave none out.
pub fn own_addresses(ifaces: &[Iface]) -> Vec<IpAddr> {
    let mut all: Vec<IpAddr> = Vec::new();
    for iface in ifaces {
        if !all.contains(&iface.ip) {
            all.push(iface.ip);
        }
    }
    all
}

pub fn network(ifaces: &[Iface]) -> Network {
    Network {
        candidates: candidates(ifaces),
        own: own_addresses(ifaces),
    }
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (64..128).contains(&b)
}

/// The first RFC 1918 address; failing that the first that is not carrier-grade NAT space
/// (the range VPNs and some relays use). `None` when there is nothing sensible.
pub fn default_ip(candidates: &[Candidate]) -> Option<Ipv4Addr> {
    candidates
        .iter()
        .find(|c| c.ip.is_private())
        .or_else(|| candidates.iter().find(|c| !is_cgnat(c.ip)))
        .map(|c| c.ip)
}

/// Read the system's interfaces. Only this function touches the system.
pub fn system_ifaces() -> Vec<Iface> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .map(|i| Iface {
            ip: i.ip(),
            name: i.name,
        })
        .collect()
}

pub fn system() -> Network {
    network(&system_ifaces())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: [u8; 4]) -> Iface {
        Iface {
            name: name.into(),
            ip: IpAddr::V4(Ipv4Addr::from(ip)),
        }
    }

    fn iface6(name: &str, ip: &str) -> Iface {
        Iface {
            name: name.into(),
            ip: ip.parse().unwrap(),
        }
    }

    #[test]
    fn own_addresses_are_every_address_on_every_interface() {
        let list = [
            iface("lo0", [127, 0, 0, 1]),
            iface6("lo0", "::1"),
            iface("utun3", [100, 64, 0, 2]),
            iface6("utun3", "fd7a:115c:a1e0::2"),
            iface("en0", [192, 168, 4, 109]),
            iface6("en0", "fe80::1c2d:3e4f:5a6b:7c8d"),
            iface6("en0", "2001:db8:1:2::109"),
            iface("en5", [203, 0, 113, 7]),
            iface("awdl0", [169, 254, 3, 3]),
        ];
        let net = network(&list);
        let expected: Vec<IpAddr> = [
            "127.0.0.1",
            "::1",
            "100.64.0.2",
            "fd7a:115c:a1e0::2",
            "192.168.4.109",
            "fe80::1c2d:3e4f:5a6b:7c8d",
            "2001:db8:1:2::109",
            "203.0.113.7",
            "169.254.3.3",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        assert_eq!(net.own, expected, "nothing is left out, in either family");
        // The choice offered to the person is still IPv4 LAN addresses only.
        let offered: Vec<String> = net.candidates.iter().map(|c| c.ip.to_string()).collect();
        assert_eq!(offered, ["192.168.4.109", "203.0.113.7"]);

        // The same address reported twice is listed once.
        let twice = [iface("en0", [10, 0, 0, 5]), iface("en0", [10, 0, 0, 5])];
        assert_eq!(own_addresses(&twice).len(), 1);
    }

    #[test]
    fn picks_private_lan_address() {
        let list = [
            iface("lo0", [127, 0, 0, 1]),
            iface("utun3", [100, 64, 0, 2]),
            iface("en0", [192, 168, 4, 109]),
        ];
        let c = candidates(&list);
        assert_eq!(default_ip(&c), Some(Ipv4Addr::new(192, 168, 4, 109)));
        // Neither the loopback nor the tunnel address is even offered.
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].label, "Wi-Fi (en0)");
    }

    #[test]
    fn private_beats_public_and_order_decides_among_private() {
        let list = [
            iface("en5", [203, 0, 113, 7]),
            iface("en7", [10, 0, 0, 5]),
            iface("en0", [192, 168, 1, 2]),
        ];
        let c = candidates(&list);
        assert_eq!(c.len(), 3);
        assert_eq!(default_ip(&c), Some(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(c[0].label, "Ethernet (en5)");
    }

    #[test]
    fn link_local_and_cgnat_are_not_defaults() {
        let list = [
            iface("en0", [169, 254, 3, 3]),
            iface("en1", [100, 70, 1, 1]),
        ];
        let c = candidates(&list);
        assert_eq!(c.len(), 1, "link-local is never offered");
        assert_eq!(default_ip(&c), None, "CGNAT-only is not a LAN address");
    }

    #[test]
    fn no_network_means_no_default() {
        assert_eq!(
            default_ip(&candidates(&[iface("lo0", [127, 0, 0, 1])])),
            None
        );
    }
}
