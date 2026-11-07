//! Networking for `jailer run --vnet`, as a Legion node gives a pod, with
//! Legion's own `PodNetwork`: an epair whose host end joins a bridge and
//! whose other end moves into the pod's jail, with the bridge as its
//! default route. The bridge is jailer's own, `jailer0` on 10.77.0.0/16 or
//! what `--pod-subnet` gives (not 10.88.0.0/16, Podman's default network),
//! IPv4 only and with Ethernet's MTU, so that a host that is also a Legion
//! node keeps its `legion0` to itself. NAT to the outside and
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
use std::sync::OnceLock;

use legion_net::PodNetwork;
pub use legion_net::lb::Proto;
use legion_sys::{Ipv4Net, Sys};

use crate::Error;

pub const BRIDGE: &str = "jailer0";
pub const DEFAULT_SUBNET: Ipv4Net = Ipv4Net {
    addr: Ipv4Addr::new(10, 77, 0, 0),
    prefix: 16,
};
static CHOSEN_SUBNET: OnceLock<Ipv4Net> = OnceLock::new();

/// Pods' network for this process, set once from `--pod-subnet`.
pub fn choose_subnet(subnet: Ipv4Net) {
    let _ = CHOSEN_SUBNET.set(subnet);
}

/// Pods' network: `--pod-subnet`'s, or jailer's own.
pub fn subnet() -> Ipv4Net {
    CHOSEN_SUBNET.get().copied().unwrap_or(DEFAULT_SUBNET)
}

/// `--pod-subnet`'s value: a network with room for a bridge and pods.
pub fn parse_subnet(text: &str) -> Result<Ipv4Net, String> {
    let net: Ipv4Net = text
        .parse()
        .map_err(|_| format!("{text}: not an IPv4 network, as 10.77.0.0/16"))?;
    if !(8..=30).contains(&net.prefix) {
        return Err(format!("{text}: the prefix must be from 8 to 30"));
    }
    if net.addr != net.network() {
        return Err(format!("{text}: that is not the network's first address"));
    }
    Ok(net)
}
/// Where addresses taken are kept; gone at boot, as the jails are.
pub const LEASES: &str = "/var/run/jailer/net";
/// What the host's pf.conf must hold for jailer's anchors to be used.
pub const HOOKS: [&str; 3] = [
    "nat-anchor \"jailer/*\"",
    "rdr-anchor \"jailer/*\"",
    "anchor \"jailer/*\"",
];
const NAT_ANCHOR: &str = "jailer/nat";

/// jailer's bridge, as Legion's pod network code makes it.
pub fn network() -> PodNetwork {
    PodNetwork::new(subnet())
        .named(BRIDGE, "jp")
        .expect("valid interface names")
        .without_v6()
        .with_mtu(1500)
}

/// The bridge's address, every pod's default route.
pub fn gateway() -> Ipv4Addr {
    network().gateway()
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
            // `0.0.0.0` is every address, as no address given is.
            [ip, h, c] => (
                Some(ip.parse::<Ipv4Addr>().map_err(|_| bad())?).filter(|a| !a.is_unspecified()),
                h,
                c,
            ),
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
    legion_net::lb::missing_hooks_of(main_rules, "jailer/*", HOOKS)
}

/// The interface that `route -n get` says an address in jailer's subnet
/// goes out of, if a route other than the default one covers it.
pub fn subnet_route(route_get: &str) -> Option<&str> {
    let field = |name: &str| {
        route_get
            .lines()
            .filter_map(|l| l.trim().strip_prefix(name))
            .map(str::trim)
            .next()
    };
    match field("destination:") {
        None | Some("default") | Some("0.0.0.0") => None,
        Some(_) => field("interface:"),
    }
}

/// Fails if another interface, a VPN's or a network another tool made,
/// already routes jailer's subnet: the pods' traffic would go there
/// instead.
pub fn check_subnet() -> Result<(), Error> {
    #[cfg(target_os = "freebsd")]
    {
        let subnet = subnet();
        let probe = Ipv4Addr::from(u32::from(subnet.addr) + 2).to_string();
        let out = std::process::Command::new("/sbin/route")
            .args(["-n", "get", &probe])
            .output()?;
        if let Some(other) = subnet_route(&String::from_utf8_lossy(&out.stdout))
            && other != BRIDGE
        {
            return Err(Error::Runtime(format!(
                "jailer's pod network {}/{} is routed to {other}, not {BRIDGE}: another network has the same addresses; remove it, choose another with --pod-subnet, or use --network none",
                subnet.addr, subnet.prefix
            )));
        }
    }
    Ok(())
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
    network().ensure_bridge(sys)?;
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
    let subnet = subnet();
    format!("nat on {egress} inet from {subnet} to ! {subnet} -> ({egress})\n")
}

/// The pf rules publishing `ports` of the pod at `ip`. They leave the
/// bridge out: a pod reaches another by its address. With no address
/// given, a port is published on the host's own addresses, as Docker
/// does: `(self)` follows them as they change. A host that routes
/// does not hand a pod what is on its way to another machine.
pub fn rdr_rules(ip: Ipv4Addr, ports: &[Port]) -> String {
    ports
        .iter()
        .map(|p| {
            format!(
                "rdr pass on ! {BRIDGE} inet proto {} from any to {} port {} -> {ip} port {}\n",
                p.proto.as_str(),
                p.host_ip.map_or("(self)".to_owned(), |a| a.to_string()),
                p.host,
                p.container
            )
        })
        .collect()
}

/// The host end of a pod's epair: `jp` and the last 12 characters of its
/// id, within the 15-character limit.
pub fn host_interface(pod: &str) -> String {
    network().host_interface(pod)
}

fn anchor(pod: &str) -> String {
    format!("jailer/{}", &pod[pod.len().saturating_sub(12)..])
}

/// Gives the pod (its jail named `pod`) the address `ip` on the bridge,
/// and publishes `ports` to it.
pub fn attach(sys: &dyn Sys, pod: &str, ip: Ipv4Addr, ports: &[Port]) -> Result<(), Error> {
    let net = network();
    net.attach(sys, pod, pod, ip)?;
    if !ports.is_empty()
        && let Err(e) = sys.pf_load_anchor(&anchor(pod), &rdr_rules(ip, ports))
    {
        let _ = net.detach(sys, pod);
        return Err(e.into());
    }
    Ok(())
}

/// Takes the pod's ports and epair away, wherever its jail end is. Both
/// are tried; failing, the pod's address must stay taken, as its
/// redirects may still be there for whoever had it next.
pub fn detach(sys: &dyn Sys, pod: &str) -> Result<(), Error> {
    let ports = sys
        .pf_flush_anchor(&anchor(pod))
        .map_err(|e| Error::Runtime(format!("removing the ports of pod {pod}: {e}")));
    let epair = network()
        .detach(sys, pod)
        .map_err(|e| Error::Runtime(format!("removing the epair of pod {pod}: {e}")));
    ports.and(epair)
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
    /// The leases whose jails are still there. One whose jail is gone, as
    /// when it was removed outside jailer, is dropped with its pf rules and
    /// epair, which would otherwise still take its ports.
    fn live(&self, sys: &dyn Sys) -> Result<Vec<(Ipv4Addr, Lease)>, Error> {
        self.live_with(sys, |jail| detach(sys, jail))
    }

    /// [`Self::live`], taking a gone jail's pf rules and epair away with
    /// `teardown`. One that fails keeps the lease, and the address with it,
    /// to try again next time.
    fn live_with(
        &self,
        sys: &dyn Sys,
        teardown: impl Fn(&str) -> Result<(), Error>,
    ) -> Result<Vec<(Ipv4Addr, Lease)>, Error> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.leases.dir)? {
            let entry = entry?;
            let Ok(ip) = entry.file_name().to_string_lossy().parse::<Ipv4Addr>() else {
                continue;
            };
            let Some(lease) = read(&entry.path()) else {
                continue;
            };
            // Only a jail known to be gone frees its address.
            if matches!(
                sys.jail_get(&lease.jail, &[]),
                Err(legion_sys::Error::NotFound(_))
            ) && teardown(&lease.jail).is_ok()
            {
                let _ = std::fs::remove_file(entry.path());
            } else {
                out.push((ip, lease));
            }
        }
        Ok(out)
    }

    /// Refused while a pod runs on another network than this process's:
    /// the bridge has one address, and taking it would cut that pod off.
    pub fn same_network(&self, sys: &dyn Sys) -> Result<(), Error> {
        let net = network();
        match self.live(sys)?.iter().find(|(ip, _)| !net.contains(*ip)) {
            Some((ip, lease)) => Err(Error::Runtime(format!(
                "jail {} has {ip}, outside the pod network {}: stop it first, or give the --pod-subnet it runs on",
                lease.jail,
                subnet()
            ))),
            None => Ok(()),
        }
    }

    /// The lowest free address, refused if another pod publishes one of
    /// `ports` already.
    pub fn allocate(&self, sys: &dyn Sys, ports: &[Port]) -> Result<Ipv4Addr, Error> {
        for (i, p) in ports.iter().enumerate() {
            if ports[..i].iter().any(|q| p.clashes(q)) {
                return Err(Error::Runtime(format!(
                    "port {}/{} is given twice",
                    p.host,
                    p.proto.as_str()
                )));
            }
        }
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
        let subnet = subnet();
        let last = u32::from(subnet.addr) + (1u32 << (32 - u32::from(subnet.prefix))) - 2;
        (first..=last)
            .map(Ipv4Addr::from)
            .find(|ip| !used.contains(ip))
            .ok_or_else(|| Error::Runtime(format!("no address left in {subnet}")))
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
    fn another_interface_routing_the_subnet_is_found() {
        let get = |dest: &str, iface: &str| {
            format!(
                "   route to: 10.77.0.2\ndestination: {dest}\n       mask: 255.255.0.0\n        fib: 0\n  interface: {iface}\n      flags: <UP,DONE>\n"
            )
        };
        assert_eq!(subnet_route(&get("10.77.0.0", "jailer0")), Some("jailer0"));
        assert_eq!(subnet_route(&get("10.0.0.0", "tun0")), Some("tun0"));
        assert_eq!(subnet_route(&get("default", "re0")), None);
        assert_eq!(subnet_route(""), None);
    }

    #[test]
    fn ports_read_as_docker_writes_them() {
        let p: Port = "8080:80".parse().unwrap();
        assert_eq!(
            (p.host_ip, p.host, p.container, p.proto),
            (None, 8080, 80, Proto::Tcp)
        );
        let p: Port = "127.0.0.1:53:5353/udp".parse().unwrap();
        assert_eq!(p.to_string(), "127.0.0.1:53:5353/udp");
        // Every address of the host, which pf calls `(self)`.
        let p: Port = "0.0.0.0:8080:80".parse().unwrap();
        assert_eq!(p.host_ip, None);
        assert!(rdr_rules(Ipv4Addr::new(10, 77, 0, 2), &[p]).contains("to (self) port 8080"));
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
    fn a_pod_subnet_must_be_a_network_with_room() {
        let net = parse_subnet("192.168.50.0/24").unwrap();
        assert_eq!(net.to_string(), "192.168.50.0/24");
        assert!(
            parse_subnet("10.77.0.1/16")
                .unwrap_err()
                .contains("first address")
        );
        assert!(parse_subnet("10.0.0.0/31").unwrap_err().contains("prefix"));
        assert!(parse_subnet("10.0.0.0/7").unwrap_err().contains("prefix"));
        assert!(
            parse_subnet("fd00::/64")
                .unwrap_err()
                .contains("not an IPv4")
        );
        assert!(parse_subnet("pods").unwrap_err().contains("not an IPv4"));
    }

    #[test]
    fn a_pod_on_another_network_keeps_the_bridge_until_it_is_gone() {
        let t = tempfile::tempdir().unwrap();
        let sys = FakeSys::new();
        sys.add_jail("old", true);
        let leases = Leases::new(t.path());
        let held = leases.lock().unwrap();
        held.record(Ipv4Addr::new(10, 79, 0, 2), "old", &[])
            .unwrap();
        let err = held.same_network(&sys).unwrap_err().to_string();
        assert!(
            err.contains("10.79.0.2") && err.contains("--pod-subnet"),
            "{err}"
        );
        // Gone, it is no reason to refuse.
        sys.remove_jail("old");
        held.same_network(&sys).unwrap();
        // And one on this network never was.
        sys.add_jail("new", true);
        held.record(Ipv4Addr::new(10, 77, 0, 2), "new", &[])
            .unwrap();
        held.same_network(&sys).unwrap();
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
            "nat on re0 inet from 10.77.0.0/16 to ! 10.77.0.0/16 -> (re0)\n"
        );

        let tmp = tempfile::tempdir().unwrap();
        let leases = Leases::new(tmp.path());
        let pod = "0123456789abcdef0123";
        sys.add_jail(pod, true);
        let ports = ["8080:80".parse().unwrap()];
        let held = leases.lock().unwrap();
        let ip = held.allocate(&sys, &ports).unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 77, 0, 2));
        held.record(ip, pod, &ports).unwrap();
        attach(&sys, pod, ip, &ports).unwrap();
        assert_eq!(
            sys.routes(Some(pod)).get(&legion_sys::Destination::Default),
            Some(&gateway().into())
        );
        assert!(
            !sys.routes(Some(pod))
                .contains_key(&legion_sys::Destination::Default6),
            "no IPv6 route"
        );
        assert_eq!(
            sys.anchor("jailer/89abcdef0123").unwrap(),
            "rdr pass on ! jailer0 inet proto tcp from any to (self) port 8080 -> 10.77.0.2 port 80\n"
        );

        // The next pod gets the next address, and not the same port.
        let next = held.allocate(&sys, &[]).unwrap();
        assert_eq!(next, Ipv4Addr::new(10, 77, 0, 3));
        let clash = held
            .allocate(&sys, &["10.0.0.1:8080:81".parse().unwrap()])
            .unwrap_err();
        assert!(clash.to_string().contains("8080/tcp"), "{clash}");
        let twice = held
            .allocate(
                &sys,
                &["9090:80".parse().unwrap(), "9090:81".parse().unwrap()],
            )
            .unwrap_err();
        assert!(twice.to_string().contains("given twice"), "{twice}");
        drop(held);

        // Releasing a lease as another pod changes nothing.
        leases.release(ip, "someone-else").unwrap();
        assert!(tmp.path().join("10.77.0.2").exists());

        // A lease whose jail is gone, but whose pf rules or epair cannot be
        // taken away, keeps its address and ports: its redirects would
        // reach the next pod given it.
        sys.remove_jail(pod);
        {
            let held = leases.lock().unwrap();
            let live = held
                .live_with(&sys, |_| Err(Error::Runtime("pfctl: busy".to_owned())))
                .unwrap();
            assert!(live.iter().any(|(i, l)| *i == ip && l.jail == pod));
            assert!(tmp.path().join("10.77.0.2").exists());
            assert!(sys.anchor("jailer/89abcdef0123").is_some());
        }

        // Once they go, it is free again, its ports and epair with it.
        assert_eq!(leases.lock().unwrap().allocate(&sys, &[]).unwrap(), ip);
        assert!(!tmp.path().join("10.77.0.2").exists());
        assert!(sys.interface(&host_interface(pod)).is_none());
        assert_eq!(
            sys.anchor("jailer/89abcdef0123").as_deref().unwrap_or(""),
            ""
        );
        leases.release(ip, pod).unwrap();
    }
}
