//! Networking for `jailer run --vnet`, as a Legion node gives a pod: an
//! epair whose host end joins a bridge and whose other end moves into the
//! pod's jail, with the bridge as its default route. The bridge is
//! jailer's own, `jailer0` on 10.88.0.0/16, so that a host that is also a
//! Legion node keeps its `legion0` to itself. NAT to the outside and
//! published ports are pf rules in anchors under `jailer/`, which the
//! host's pf.conf must call.
//!
//! Addresses are the host's, whatever state directory a container's is
//! in: each one taken is a file in [`LEASES`] naming the pod's jail, and
//! an address whose jail is gone is free again.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use legion_sys::{Destination, IfConfig, Ipv4Net, Sys};

use crate::Error;

pub const BRIDGE: &str = "jailer0";
pub const SUBNET: Ipv4Net = Ipv4Net {
    addr: Ipv4Addr::new(10, 88, 0, 0),
    prefix: 16,
};
/// Where addresses taken are kept; gone at boot, as the jails are.
pub const LEASES: &str = "/var/run/jailer/net";
/// What the host's pf.conf must hold for jailer's anchors to be used.
pub const HOOKS: [&str; 3] = [
    "nat-anchor \"jailer/*\"",
    "rdr-anchor \"jailer/*\"",
    "anchor \"jailer/*\"",
];
const NAT_ANCHOR: &str = "jailer/nat";

/// The bridge's address, every pod's default route.
pub fn gateway() -> Ipv4Addr {
    Ipv4Addr::from(u32::from(SUBNET.addr) + 1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// A published port: `-p [IP:]HOST:CONTAINER[/tcp|udp]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Port {
    /// The host address it is published on; none for all of them.
    pub host_ip: Option<Ipv4Addr>,
    pub host: u16,
    pub container: u16,
    pub proto: Proto,
}

impl FromStr for Port {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let bad = || {
            Error::Runtime(format!(
                "-p {s:?}: give [IP:]HOST:CONTAINER[/tcp|udp], e.g. 8080:80"
            ))
        };
        let (ports, proto) = match s.rsplit_once('/') {
            Some((p, "tcp")) => (p, Proto::Tcp),
            Some((p, "udp")) => (p, Proto::Udp),
            Some(_) => return Err(bad()),
            None => (s, Proto::Tcp),
        };
        let parts: Vec<&str> = ports.split(':').collect();
        let (host_ip, host, container) = match parts[..] {
            [h, c] => (None, h, c),
            [ip, h, c] => (Some(ip.parse().map_err(|_| bad())?), h, c),
            _ => return Err(bad()),
        };
        let port = |p: &str| p.parse::<u16>().ok().filter(|&n| n > 0).ok_or_else(bad);
        Ok(Port {
            host_ip,
            host: port(host)?,
            container: port(container)?,
            proto,
        })
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ip) = self.host_ip {
            write!(f, "{ip}:")?;
        }
        write!(
            f,
            "{}:{}/{}",
            self.host,
            self.container,
            self.proto.as_str()
        )
    }
}

impl Port {
    /// Whether both take the same host port.
    fn clashes(&self, other: &Port) -> bool {
        self.host == other.host
            && self.proto == other.proto
            && (self.host_ip.is_none() || other.host_ip.is_none() || self.host_ip == other.host_ip)
    }
}

/// The hooks the host's main pf ruleset lacks.
pub fn missing_hooks(main_rules: &str) -> Vec<&'static str> {
    let called = |kind: &str| {
        main_rules.lines().any(|l| {
            let l = l.trim();
            l.starts_with(kind) && l.contains("\"jailer/*\"")
        })
    };
    ["nat-anchor", "rdr-anchor", "anchor"]
        .into_iter()
        .zip(HOOKS)
        .filter(|(kind, _)| !called(kind))
        .map(|(_, hook)| hook)
        .collect()
}

/// Makes the bridge, turns on forwarding and loads the NAT rules: what
/// every pod on the bridge needs. Fails, saying what to add, if pf.conf
/// does not call jailer's anchors.
pub fn ensure(sys: &dyn Sys) -> Result<(), Error> {
    let main = sys.pf_main_rules().map_err(|e| {
        Error::Runtime(format!(
            "--vnet networking needs pf(4), with jailer's anchors: {e}"
        ))
    })?;
    let missing = missing_hooks(&main);
    if !missing.is_empty() {
        return Err(Error::Runtime(format!(
            "--vnet networking needs pf.conf to call jailer's anchors: add\n    {}\nwith the NAT and redirect anchors before any filter rule, then run `pfctl -f /etc/pf.conf` (or use --network none)",
            missing.join("\n    ")
        )));
    }
    if !sys.interfaces(None)?.iter().any(|i| i == BRIDGE) {
        sys.bridge_create(BRIDGE)?;
    }
    sys.interface_configure(
        None,
        BRIDGE,
        &IfConfig {
            addr: Some(Ipv4Net::new(gateway(), SUBNET.prefix)),
            up: true,
            ..Default::default()
        },
    )?;
    if sys.sysctl_get("net.inet.ip.forwarding").ok().as_deref() != Some("1") {
        sys.sysctl_set("net.inet.ip.forwarding", "1")?;
    }
    match sys.default_interface()? {
        Some(egress) => sys.pf_load_anchor(NAT_ANCHOR, &nat_rules(&egress))?,
        // No way out to translate for; the pods still reach the host.
        None => sys.pf_flush_anchor(NAT_ANCHOR)?,
    }
    Ok(())
}

pub fn nat_rules(egress: &str) -> String {
    format!("nat on {egress} inet from {SUBNET} to ! {SUBNET} -> ({egress})\n")
}

/// The pf rules publishing `ports` of the pod at `ip`. They leave the
/// bridge out: a pod reaches another by its address.
pub fn rdr_rules(ip: Ipv4Addr, ports: &[Port]) -> String {
    ports
        .iter()
        .map(|p| {
            format!(
                "rdr pass on ! {BRIDGE} inet proto {} from any to {} port {} -> {ip} port {}\n",
                p.proto.as_str(),
                p.host_ip.map_or("any".to_owned(), |a| a.to_string()),
                p.host,
                p.container
            )
        })
        .collect()
}

/// The host end of a pod's epair: `jp` and the last 12 characters of its
/// id, within the 15-character limit.
pub fn host_interface(pod: &str) -> String {
    format!("jp{}", &pod[pod.len().saturating_sub(12)..])
}

fn anchor(pod: &str) -> String {
    format!("jailer/{}", &pod[pod.len().saturating_sub(12)..])
}

/// Gives the pod (its jail named `pod`) the address `ip` on the bridge,
/// and publishes `ports` to it.
pub fn attach(sys: &dyn Sys, pod: &str, ip: Ipv4Addr, ports: &[Port]) -> Result<(), Error> {
    let host = host_interface(pod);
    let pair = sys.epair_create()?;
    let result = (|| {
        sys.interface_rename(&pair.a, &host)?;
        // With the bridge's Ethernet address, the pod's ARP for the gateway
        // is answered with the bridge's, as on a Legion node.
        sys.interface_set_ether(&host, &sys.interface_ether(BRIDGE)?)?;
        sys.interface_configure(
            None,
            &host,
            &IfConfig {
                up: true,
                ..Default::default()
            },
        )?;
        sys.bridge_add_member(BRIDGE, &host)?;
        sys.interface_move(&pair.b, pod)?;
        sys.interface_configure(
            Some(pod),
            &pair.b,
            &IfConfig {
                addr: Some(Ipv4Net::new(ip, SUBNET.prefix)),
                up: true,
                ..Default::default()
            },
        )?;
        sys.route_add(Some(pod), Destination::Default, gateway().into())?;
        if !ports.is_empty() {
            sys.pf_load_anchor(&anchor(pod), &rdr_rules(ip, ports))?;
        }
        Ok::<_, legion_sys::Error>(())
    })();
    if let Err(e) = result {
        // Either end name works until the rename; try both.
        for name in [&host, &pair.a] {
            if sys.interface_destroy(name).is_ok() {
                break;
            }
        }
        let _ = sys.pf_flush_anchor(&anchor(pod));
        return Err(e.into());
    }
    Ok(())
}

/// Takes the pod's ports and epair away, wherever its jail end is.
pub fn detach(sys: &dyn Sys, pod: &str) {
    let _ = sys.pf_flush_anchor(&anchor(pod));
    let host = host_interface(pod);
    if sys
        .interfaces(None)
        .is_ok_and(|names| names.contains(&host))
    {
        let _ = sys.interface_destroy(&host);
    }
}

/// The addresses taken on the bridge, one file each, naming the pod's jail
/// and its published ports.
pub struct Leases {
    dir: PathBuf,
}

/// [`Leases`] locked against other jailer processes until dropped.
pub struct Locked<'a> {
    leases: &'a Leases,
    _lock: File,
}

struct Lease {
    jail: String,
    ports: Vec<Port>,
}

impl Leases {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Leases { dir: dir.into() }
    }

    pub fn lock(&self) -> Result<Locked<'_>, Error> {
        std::fs::create_dir_all(&self.dir)?;
        let lock = File::create(self.dir.join(".lock"))?;
        lock.lock()?;
        Ok(Locked {
            leases: self,
            _lock: lock,
        })
    }

    fn path(&self, ip: Ipv4Addr) -> PathBuf {
        self.dir.join(ip.to_string())
    }

    /// Gives `ip` back, if the pod in `jail` still holds it.
    pub fn release(&self, ip: Ipv4Addr, jail: &str) -> Result<(), Error> {
        let _held = self.lock()?;
        if read(&self.path(ip)).is_some_and(|l| l.jail == jail) {
            std::fs::remove_file(self.path(ip))?;
        }
        Ok(())
    }
}

impl Locked<'_> {
    /// The leases whose jails are still there.
    fn live(&self, sys: &dyn Sys) -> Result<Vec<(Ipv4Addr, Lease)>, Error> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.leases.dir)? {
            let entry = entry?;
            let Ok(ip) = entry.file_name().to_string_lossy().parse::<Ipv4Addr>() else {
                continue;
            };
            // Only a jail known to be gone frees its address.
            if let Some(lease) = read(&entry.path())
                && !matches!(
                    sys.jail_get(&lease.jail, &[]),
                    Err(legion_sys::Error::NotFound(_))
                )
            {
                out.push((ip, lease));
            }
        }
        Ok(out)
    }

    /// The lowest free address, refused if another pod publishes one of
    /// `ports` already.
    pub fn allocate(&self, sys: &dyn Sys, ports: &[Port]) -> Result<Ipv4Addr, Error> {
        let live = self.live(sys)?;
        for (_, lease) in &live {
            if let Some(p) = ports
                .iter()
                .find(|p| lease.ports.iter().any(|q| p.clashes(q)))
            {
                return Err(Error::Runtime(format!(
                    "port {}/{} is published already, by jail {}",
                    p.host,
                    p.proto.as_str(),
                    lease.jail
                )));
            }
        }
        let used: BTreeSet<Ipv4Addr> = live.iter().map(|(ip, _)| *ip).collect();
        let first = u32::from(gateway()) + 1;
        let last = u32::from(SUBNET.addr) + (1u32 << (32 - u32::from(SUBNET.prefix))) - 2;
        (first..=last)
            .map(Ipv4Addr::from)
            .find(|ip| !used.contains(ip))
            .ok_or_else(|| Error::Runtime(format!("no address left in {SUBNET}")))
    }

    /// Records `ip` as the pod's in `jail`.
    pub fn record(&self, ip: Ipv4Addr, jail: &str, ports: &[Port]) -> Result<(), Error> {
        let mut text = format!("{jail}\n");
        for p in ports {
            text.push_str(&format!("{p}\n"));
        }
        std::fs::write(self.leases.path(ip), text)?;
        Ok(())
    }
}

fn read(path: &Path) -> Option<Lease> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut lines = text.lines();
    let jail = lines.next()?.to_owned();
    let ports = lines.filter_map(|l| l.parse().ok()).collect();
    Some(Lease { jail, ports })
}

#[cfg(test)]
mod tests {
    use legion_sys::FakeSys;

    use super::*;

    #[test]
    fn ports_read_as_docker_writes_them() {
        let p: Port = "8080:80".parse().unwrap();
        assert_eq!(
            (p.host_ip, p.host, p.container, p.proto),
            (None, 8080, 80, Proto::Tcp)
        );
        let p: Port = "127.0.0.1:53:5353/udp".parse().unwrap();
        assert_eq!(p.to_string(), "127.0.0.1:53:5353/udp");
        for bad in ["80", "a:80", "0:80", "1:2:3:4", "8080:80/sctp", "x:1:2"] {
            assert!(bad.parse::<Port>().is_err(), "{bad}");
        }
    }

    #[test]
    fn hooks_are_found_in_the_main_ruleset() {
        let main =
            "nat-anchor \"legion/*\" all\nnat-anchor \"jailer/*\" all\nanchor \"jailer/*\" all\n";
        assert_eq!(missing_hooks(main), [HOOKS[1]]);
        let sys = FakeSys::new();
        sys.set_main_rules(main);
        let err = ensure(&sys).unwrap_err().to_string();
        assert!(err.contains("rdr-anchor \"jailer/*\""), "{err}");
    }

    #[test]
    fn pods_get_an_address_a_route_and_their_ports() {
        let sys = FakeSys::new();
        sys.set_main_rules(&HOOKS.join("\n"));
        sys.set_default_interface("re0");
        ensure(&sys).unwrap();
        assert_eq!(sys.sysctl("net.inet.ip.forwarding").as_deref(), Some("1"));
        assert_eq!(
            sys.anchor(NAT_ANCHOR).unwrap(),
            "nat on re0 inet from 10.88.0.0/16 to ! 10.88.0.0/16 -> (re0)\n"
        );

        let tmp = tempfile::tempdir().unwrap();
        let leases = Leases::new(tmp.path());
        let pod = "0123456789abcdef0123";
        sys.add_jail(pod, true);
        let ports = ["8080:80".parse().unwrap()];
        let held = leases.lock().unwrap();
        let ip = held.allocate(&sys, &ports).unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 88, 0, 2));
        held.record(ip, pod, &ports).unwrap();
        attach(&sys, pod, ip, &ports).unwrap();
        assert_eq!(
            sys.routes(Some(pod)).get(&Destination::Default),
            Some(&gateway().into())
        );
        assert_eq!(
            sys.anchor("jailer/89abcdef0123").unwrap(),
            "rdr pass on ! jailer0 inet proto tcp from any to any port 8080 -> 10.88.0.2 port 80\n"
        );

        // The next pod gets the next address, and not the same port.
        let next = held.allocate(&sys, &[]).unwrap();
        assert_eq!(next, Ipv4Addr::new(10, 88, 0, 3));
        let clash = held
            .allocate(&sys, &["10.0.0.1:8080:81".parse().unwrap()])
            .unwrap_err();
        assert!(clash.to_string().contains("8080/tcp"), "{clash}");
        drop(held);

        // A lease whose jail is gone is free again; releasing it as
        // another pod changes nothing.
        leases.release(ip, "someone-else").unwrap();
        assert!(tmp.path().join("10.88.0.2").exists());
        sys.remove_jail(pod);
        assert_eq!(leases.lock().unwrap().allocate(&sys, &[]).unwrap(), ip);
        leases.release(ip, pod).unwrap();
        assert!(!tmp.path().join("10.88.0.2").exists());

        detach(&sys, pod);
        assert!(sys.interface(&host_interface(pod)).is_none());
        assert_eq!(
            sys.anchor("jailer/89abcdef0123").as_deref().unwrap_or(""),
            ""
        );
    }
}
