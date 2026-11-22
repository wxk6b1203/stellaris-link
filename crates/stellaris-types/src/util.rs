use std::net::IpAddr;

/// A single-host prefix for an overlay IP: /32 for IPv4, /128 for IPv6.
pub fn host_prefix(ip: IpAddr) -> ipnet::IpNet {
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    ipnet::IpNet::new(ip, prefix).expect("host prefix")
}
