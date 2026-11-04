//! Containers are Legion's: `legion_jail::JailRuntime` runs them, as a
//! node does, and runs a build's `RUN` steps. What is jailer's own is how
//! `jailer run` asks for one: a standalone container (a jail of its own on
//! the host's network), or with `--vnet` a pod jail and a member in it, as
//! a cluster runs a pod, the pod on jailer's bridge ([`crate::net`]). Containers get Legion's security defaults, with
//! `--param` over them.

use std::collections::BTreeMap;

pub use legion_jail::{
    ANNOTATION_CPUSET, ANNOTATION_JAIL, ANNOTATION_MLOCK, ANNOTATION_PARENT, ANNOTATION_SYSV,
    ANNOTATION_VNET, DEVFS_RULESET, LINUX_MODULES,
};
pub use legion_runtime::{ContainerSpec, Mount};
use legion_sys::{RctlRule, Resource, Sys};

#[cfg(not(unix))]
pub use elsewhere::{Config, JailRuntime, Step, StepMount, StepNetwork};
#[cfg(unix)]
pub use legion_jail::{Config, JailRuntime, Step, StepMount, StepNetwork};

use crate::Error;

/// On a member jailer made a pod for: the pod's id.
pub const LABEL_POD: &str = "jailer.pod";
/// `pod` on a pod jailer made; `jailer ps` leaves them out.
pub const LABEL_ROLE: &str = "jailer.role";
/// On a pod on the bridge: its address.
pub const LABEL_IP: &str = "jailer.ip";
/// On a pod on the bridge: the ports it publishes, comma-separated.
pub const LABEL_PORTS: &str = "jailer.ports";

/// The network a container is on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Network {
    /// The host's, in a jail of its own.
    #[default]
    Host,
    /// A pod's VNET, on jailer's bridge.
    Bridge,
    /// A pod's VNET with only its loopback.
    None,
}

/// What `jailer run` asks for.
#[derive(Debug, Clone, Default)]
pub struct RunSpec {
    pub name: String,
    /// As the store names it.
    pub image: String,
    pub entrypoint: Vec<String>,
    pub command: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub user: Option<String>,
    pub work_dir: Option<String>,
    pub hostname: Option<String>,
    pub mounts: Vec<Mount>,
    /// jail(8) parameters, over Legion's security defaults.
    pub params: Vec<(String, String)>,
    pub network: Network,
    /// Published, with [`Network::Bridge`].
    pub ports: Vec<crate::net::Port>,
    pub allow_mlock: bool,
    /// `msg`, `sem`, `shm`.
    pub sysv: Vec<String>,
    pub limits: Limits,
    /// The CPUs it may run on, as `cpuset -l` takes them.
    pub cpuset: Option<String>,
}

/// Resource limits for a container or a build's `RUN` steps, held by
/// rctl(8) rules on the jail. A rule may name a jail before it exists, so
/// they are set before anything runs in it.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Limits {
    /// Bytes of resident memory for each process: one going past it is
    /// killed, as on a Legion node.
    pub memory: Option<u64>,
    /// CPUs' worth of time, as a percentage of one CPU.
    pub pcpu: Option<u64>,
    /// Processes at a time.
    pub pids: Option<u64>,
}

impl Limits {
    /// `--memory` (a size, e.g. `512m`), `--cpus` (e.g. `1.5`) and
    /// `--pids-limit`.
    pub fn parse(
        memory: Option<&str>,
        cpus: Option<&str>,
        pids: Option<u64>,
    ) -> Result<Self, Error> {
        let memory = memory
            .map(|m| {
                crate::containerfile::parse_size(m)
                    .filter(|&n| n > 0)
                    .ok_or_else(|| {
                        Error::Runtime(format!("--memory {m:?}: give a size such as 512m"))
                    })
            })
            .transpose()?;
        let pcpu = cpus
            .map(|c| match c.parse::<f64>() {
                Ok(n) if n > 0.0 && n.is_finite() => Ok(((n * 100.0).round() as u64).max(1)),
                _ => Err(Error::Runtime(format!(
                    "--cpus {c:?}: give a number of CPUs, such as 1.5"
                ))),
            })
            .transpose()?;
        if pids == Some(0) {
            return Err(Error::Runtime("--pids-limit must be at least 1".to_owned()));
        }
        Ok(Limits { memory, pcpu, pids })
    }

    pub fn is_empty(&self) -> bool {
        *self == Limits::default()
    }

    /// The rules holding these limits on `jail`.
    pub fn rules(&self, jail: &str) -> Vec<RctlRule> {
        [
            (Resource::MemoryUse, self.memory),
            (Resource::Pcpu, self.pcpu),
            (Resource::MaxProc, self.pids),
        ]
        .into_iter()
        .filter_map(|(resource, amount)| {
            amount.map(|amount| RctlRule {
                jail: jail.to_owned(),
                resource,
                amount,
            })
        })
        .collect()
    }
}

/// Sets `limits` on `jail`, replacing any rules it had.
pub fn limit(sys: &dyn Sys, jail: &str, limits: &Limits) -> Result<(), Error> {
    if limits.is_empty() {
        return Ok(());
    }
    if sys.sysctl_get("kern.racct.enable").ok().as_deref() != Some("1") {
        return Err(Error::Runtime(
            "resource limits need rctl: set kern.racct.enable=1 in /boot/loader.conf and reboot"
                .to_owned(),
        ));
    }
    unlimit(sys, jail);
    add_rules(sys, jail, &limits.rules(jail), |r| sys.rctl_add(r))
}

/// Limits set on a jail, taken away when this is dropped: however what
/// runs under them ends, by an error or cancelled.
pub(crate) struct Limited<'a> {
    sys: &'a dyn Sys,
    jail: String,
}

impl Drop for Limited<'_> {
    fn drop(&mut self) {
        unlimit(self.sys, &self.jail);
    }
}

/// [`limit`], for as long as the [`Limited`] returned lives; with no
/// limits, nothing is set or taken away.
pub(crate) fn limited<'a>(
    sys: &'a dyn Sys,
    jail: &str,
    limits: &Limits,
) -> Result<Option<Limited<'a>>, Error> {
    if limits.is_empty() {
        return Ok(None);
    }
    limit(sys, jail, limits)?;
    Ok(Some(Limited {
        sys,
        jail: jail.to_owned(),
    }))
}

/// Adds `rules` to `jail` with `add`; one that fails takes those added
/// before it away, as nothing would remove them without a container.
fn add_rules(
    sys: &dyn Sys,
    jail: &str,
    rules: &[RctlRule],
    add: impl Fn(&RctlRule) -> legion_sys::Result<()>,
) -> Result<(), Error> {
    for rule in rules {
        if let Err(e) = add(rule) {
            unlimit(sys, jail);
            return Err(Error::Runtime(format!("setting the limit {rule}: {e}")));
        }
    }
    Ok(())
}

/// Drops `jail`'s rules, if it has any.
pub fn unlimit(sys: &dyn Sys, jail: &str) {
    let _ = sys.rctl_remove_jail(jail);
}

/// The member `spec` asks for, its pod not yet named.
pub fn member_spec(spec: &RunSpec) -> Result<ContainerSpec, Error> {
    let mut jail = legion_api::security::Security::default().jail_annotation();
    for (k, v) in &spec.params {
        if k.is_empty() || k.contains(char::is_whitespace) || v.contains(char::is_whitespace) {
            return Err(Error::Runtime(format!(
                "--param {k}={v}: names and values may not hold spaces"
            )));
        }
        jail.push(' ');
        jail.push_str(k);
        if !v.is_empty() {
            jail.push('=');
            jail.push_str(v);
        }
    }
    let mut annotations = BTreeMap::from([(ANNOTATION_JAIL.to_owned(), jail)]);
    if spec.allow_mlock {
        annotations.insert(ANNOTATION_MLOCK.to_owned(), "true".to_owned());
    }
    if let Some(cpus) = &spec.cpuset {
        annotations.insert(ANNOTATION_CPUSET.to_owned(), cpus.clone());
    }
    for s in &spec.sysv {
        let wanted = sysv_param(s)?;
        let (annotation, _) = ANNOTATION_SYSV
            .iter()
            .find(|(_, param)| *param == wanted)
            .expect("a SysV parameter");
        annotations.insert((*annotation).to_owned(), "inherit".to_owned());
    }
    Ok(ContainerSpec {
        name: spec.name.clone(),
        image: spec.image.clone(),
        entrypoint: spec.entrypoint.clone(),
        command: spec.command.clone(),
        env: spec.env.clone(),
        work_dir: spec.work_dir.clone(),
        user: spec.user.clone(),
        hostname: spec.hostname.clone(),
        annotations,
        mounts: spec.mounts.clone(),
        ..Default::default()
    })
}

/// The jail parameter `--sysv` names: `sysvmsg` for `msg`.
pub fn sysv_param(kind: &str) -> Result<&'static str, Error> {
    match kind.trim() {
        "msg" | "sysvmsg" => Ok("sysvmsg"),
        "sem" | "sysvsem" => Ok("sysvsem"),
        "shm" | "sysvshm" => Ok("sysvshm"),
        other => Err(Error::Runtime(format!(
            "unknown --sysv option {other:?} (expected msg, sem, or shm)"
        ))),
    }
}

/// `build --param` (`KEY=VALUE`) and `--sysv`: jail parameters for `RUN`
/// steps, each kind of SysV IPC a step's own.
pub fn step_params(params: &[String], sysv: &[String]) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::new();
    for s in sysv {
        out.push((sysv_param(s)?.to_owned(), "new".to_owned()));
    }
    for kv in params {
        let (k, v) = kv.split_once('=').unwrap_or((kv.as_str(), ""));
        out.push((k.to_owned(), v.to_owned()));
    }
    Ok(out)
}

/// The pod a `--vnet` member runs in: a VNET jail running nothing.
pub fn pod_spec(spec: &RunSpec) -> ContainerSpec {
    ContainerSpec {
        name: format!("{}-pod", spec.name),
        image: spec.image.clone(),
        hostname: Some(spec.hostname.clone().unwrap_or_else(|| spec.name.clone())),
        labels: BTreeMap::from([(LABEL_ROLE.to_owned(), "pod".to_owned())]),
        annotations: BTreeMap::from([(ANNOTATION_VNET.to_owned(), "new".to_owned())]),
        ..Default::default()
    }
}

#[cfg(unix)]
mod containers {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use legion_runtime::Runtime;
    use legion_sys::{IfConfig, Ipv4Net};

    use super::*;
    use crate::net::{self, Leases};

    /// Creates the container `spec` asks for (and with `--vnet` starts its
    /// pod, on the bridge) and returns its id.
    pub async fn create(
        rt: &JailRuntime,
        sys: &dyn Sys,
        leases: &Leases,
        spec: &RunSpec,
    ) -> Result<String, Error> {
        let mut member = member_spec(spec)?;
        let mut pod = None;
        if spec.network != Network::Host {
            let mut pod_spec = pod_spec(spec);
            // Held until the address is recorded as the pod's.
            let mut lease = None;
            if spec.network == Network::Bridge {
                net::ensure(sys)?;
                let held = leases.lock()?;
                let ip = held.allocate(sys, &spec.ports)?;
                pod_spec.labels.insert(LABEL_IP.to_owned(), ip.to_string());
                if !spec.ports.is_empty() {
                    let ports: Vec<String> = spec.ports.iter().map(ToString::to_string).collect();
                    pod_spec
                        .labels
                        .insert(LABEL_PORTS.to_owned(), ports.join(","));
                }
                lease = Some((held, ip));
            }
            let id = rt.create(&pod_spec).await?;
            pod = Some(id.clone());
            let started = async {
                rt.start(&id).await?;
                sys.jail_set(&id, &[("children.max", "1")])?;
                // A new VNET's loopback has only ::1; the pod's members
                // expect 127.0.0.1 too, as on a node.
                sys.interface_configure(
                    Some(&id),
                    "lo0",
                    &IfConfig {
                        addr: Some(Ipv4Net::new(Ipv4Addr::LOCALHOST, 8)),
                        up: true,
                        ..Default::default()
                    },
                )?;
                if let Some((held, ip)) = &lease {
                    held.record(*ip, &id, &spec.ports)?;
                    net::attach(sys, &id, *ip, &spec.ports)?;
                }
                Ok::<_, Error>(())
            };
            if let Err(e) = started.await {
                if let Some((held, ip)) = lease {
                    // What attach did, if anything: its pf rules and epair.
                    // Left there, they keep the address, for a later
                    // allocation to take them away.
                    let torn = net::detach(sys, &id);
                    drop(held);
                    if torn.is_ok() {
                        let _ = leases.release(ip, &id);
                    }
                }
                let _ = rt.remove(&id).await;
                return Err(e);
            }
            drop(lease);
            member
                .annotations
                .insert(ANNOTATION_PARENT.to_owned(), id.clone());
            member.labels.insert(LABEL_POD.to_owned(), id);
        }
        let made = async {
            let id = rt.create(&member).await?;
            if let Err(e) = limit(sys, &jail_of(&id, pod.as_deref()), &spec.limits) {
                let _ = rt.remove(&id).await;
                return Err(e);
            }
            Ok(id)
        };
        match made.await {
            Ok(id) => Ok(id),
            Err(e) => {
                if let Some(p) = pod {
                    // Its published ports must not reach whoever takes its
                    // address next.
                    let _ = unplug(rt, sys, leases, &p).await;
                    let _ = rt.remove(&p).await;
                }
                Err(e)
            }
        }
    }

    /// The jail Legion's runtime runs container `id` in.
    fn jail_of(id: &str, pod: Option<&str>) -> String {
        match pod {
            Some(p) => format!("{p}.{id}"),
            None => id.to_owned(),
        }
    }

    /// The pod `id` runs in, if jailer made one for it.
    async fn pod_of(rt: &JailRuntime, id: &str) -> Result<Option<String>, Error> {
        Ok(rt.inspect(id).await?.config.labels.get(LABEL_POD).cloned())
    }

    /// Takes a stopped pod off the bridge and frees its address: a stopped
    /// pod does not start again. If its pf rules or epair cannot be taken
    /// away, the address stays taken (its redirects would reach whoever
    /// had it next), and a later allocation tries again once the pod's
    /// jail is gone.
    async fn unplug(
        rt: &JailRuntime,
        sys: &dyn Sys,
        leases: &Leases,
        pod: &str,
    ) -> Result<(), Error> {
        let Ok(status) = rt.inspect(pod).await else {
            return Ok(());
        };
        if let Some(ip) = status.config.labels.get(LABEL_IP) {
            net::detach(sys, pod)?;
            if let Ok(ip) = ip.parse() {
                leases.release(ip, pod)?;
            }
        }
        Ok(())
    }

    /// Stops a container, then its pod.
    pub async fn stop(
        rt: &JailRuntime,
        sys: &dyn Sys,
        leases: &Leases,
        id: &str,
        timeout: Duration,
    ) -> Result<(), Error> {
        rt.stop(id, timeout).await?;
        stop_pod(rt, sys, leases, id).await
    }

    /// Stops the pod of a container that has stopped, freeing its address
    /// and ports.
    pub async fn stop_pod(
        rt: &JailRuntime,
        sys: &dyn Sys,
        leases: &Leases,
        id: &str,
    ) -> Result<(), Error> {
        if let Some(p) = pod_of(rt, id).await? {
            match rt.stop(&p, Duration::ZERO).await {
                Err(e) if !e.is_not_found() => return Err(e.into()),
                _ => {}
            }
            unplug(rt, sys, leases, &p).await?;
        }
        Ok(())
    }

    /// Removes a container, then its pod, and the container's limits.
    pub async fn remove(
        rt: &JailRuntime,
        sys: &dyn Sys,
        leases: &Leases,
        id: &str,
    ) -> Result<(), Error> {
        let pod = pod_of(rt, id).await?;
        rt.remove(id).await?;
        unlimit(sys, &jail_of(id, pod.as_deref()));
        if let Some(p) = pod {
            // The pod goes even so: its lease, kept, outlives it.
            let unplugged = unplug(rt, sys, leases, &p).await;
            match rt.remove(&p).await {
                Err(e) if !e.is_not_found() => return Err(e.into()),
                _ => {}
            }
            unplugged?;
        }
        Ok(())
    }
}

#[cfg(unix)]
pub use containers::{create, remove, stop, stop_pod};

/// Elsewhere than FreeBSD there are no jails: the store and builds work,
/// up to a `RUN` step.
#[cfg(not(unix))]
mod elsewhere {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use legion_image::Store;
    use legion_sys::Sys;

    pub struct Config {
        pub state_dir: PathBuf,
        pub dataset: Option<String>,
        pub shim: Vec<OsString>,
        pub prune_images: bool,
    }

    pub struct JailRuntime;

    pub struct Step<'a> {
        pub name: &'a str,
        pub root: &'a Path,
        pub argv: &'a [String],
        pub env: &'a [String],
        pub user: &'a str,
        pub work_dir: &'a str,
        pub mounts: &'a [StepMount],
        pub network: StepNetwork,
        pub params: &'a [(String, String)],
        pub cpuset: Option<&'a str>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum StepMount {
        Nullfs {
            source: PathBuf,
            target: String,
            read_only: bool,
        },
        Tmpfs {
            target: String,
            size: Option<u64>,
        },
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum StepNetwork {
        Host,
        None,
    }

    impl JailRuntime {
        pub fn new(_: Arc<dyn Sys>, _: Arc<Store>, config: Config) -> std::io::Result<Self> {
            std::fs::create_dir_all(&config.state_dir)?;
            Ok(JailRuntime)
        }

        pub async fn run_step(&self, _: &Step<'_>) -> legion_runtime::Result<i32> {
            Err(legion_runtime::Error::Failed(
                "RUN steps run in jails, which need FreeBSD".to_owned(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limit_that_fails_takes_the_others_away() {
        let sys = legion_sys::FakeSys::new();
        let limits = Limits {
            memory: Some(64 << 20),
            pcpu: Some(50),
            pids: Some(10),
        };
        let rules = limits.rules("j");
        // The third fails: the two before it are gone again.
        let err = add_rules(&sys, "j", &rules, |r| {
            if r.resource == Resource::MaxProc {
                Err(legion_sys::Error::NotFound("no".to_owned()))
            } else {
                sys.rctl_add(r)
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("setting the limit"), "{err}");
        assert!(sys.rctl_rules().is_empty(), "{:?}", sys.rctl_rules());
        // All added, all are kept.
        add_rules(&sys, "j", &rules, |r| sys.rctl_add(r)).unwrap();
        assert_eq!(sys.rctl_rules().len(), 3);
    }

    #[test]
    fn limits_go_with_their_guard() {
        let sys = legion_sys::FakeSys::new();
        sys.sysctl_set("kern.racct.enable", "1").unwrap();
        let limits = Limits {
            pids: Some(10),
            ..Default::default()
        };
        let held = limited(&sys, "step", &limits).unwrap();
        assert_eq!(sys.rctl_rules().len(), 1);
        drop(held);
        assert!(sys.rctl_rules().is_empty());
        assert!(limited(&sys, "step", &Limits::default()).unwrap().is_none());
    }

    #[test]
    fn members_get_legions_defaults_with_params_over_them() {
        let spec = RunSpec {
            name: "web".to_owned(),
            image: "localhost/web:1".to_owned(),
            params: vec![
                ("securelevel".to_owned(), "0".to_owned()),
                ("allow.raw_sockets".to_owned(), String::new()),
            ],
            allow_mlock: true,
            sysv: vec!["shm".to_owned()],
            ..Default::default()
        };
        let m = member_spec(&spec).unwrap();
        let jail = &m.annotations[ANNOTATION_JAIL];
        assert!(jail.starts_with(&legion_api::security::Security::default().jail_annotation()));
        assert!(jail.ends_with(" securelevel=0 allow.raw_sockets"), "{jail}");
        assert_eq!(m.annotations[ANNOTATION_MLOCK], "true");
        assert_eq!(m.annotations["org.freebsd.jail.sysvshm"], "inherit");
        assert!(!m.annotations.contains_key(ANNOTATION_VNET));
        assert!(!m.annotations.contains_key(ANNOTATION_PARENT));

        let pod = pod_spec(&spec);
        assert_eq!(pod.name, "web-pod");
        assert_eq!(pod.annotations[ANNOTATION_VNET], "new");
        assert_eq!(pod.labels[LABEL_ROLE], "pod");

        let bad = RunSpec {
            sysv: vec!["pipe".to_owned()],
            ..spec.clone()
        };
        assert!(member_spec(&bad).is_err());
        let spaced = RunSpec {
            params: vec![("host.hostname".to_owned(), "a b".to_owned())],
            ..spec
        };
        assert!(member_spec(&spaced).is_err());
    }

    #[test]
    fn limits_become_rctl_rules() {
        let l = Limits::parse(Some("512m"), Some("1.5"), Some(64)).unwrap();
        let rules: Vec<String> = l.rules("j").iter().map(ToString::to_string).collect();
        assert_eq!(
            rules,
            [
                "jail:j:memoryuse:sigkill=536870912/process",
                "jail:j:pcpu:deny=150",
                "jail:j:maxproc:deny=64"
            ]
        );
        assert!(Limits::parse(None, None, None).unwrap().is_empty());
        assert_eq!(
            Limits::parse(None, Some("0.001"), None).unwrap().pcpu,
            Some(1)
        );
        for (m, c, p) in [
            (Some("lots"), None, None),
            (None, Some("0"), None),
            (None, Some("nan"), None),
            (None, None, Some(0)),
        ] {
            assert!(Limits::parse(m, c, p).is_err());
        }
    }

    #[test]
    fn steps_get_sysv_of_their_own_and_params() {
        let got = step_params(
            &["securelevel=1".to_owned(), "allow.raw_sockets".to_owned()],
            &["shm".to_owned(), "sysvmsg".to_owned()],
        )
        .unwrap();
        let want = [
            ("sysvshm", "new"),
            ("sysvmsg", "new"),
            ("securelevel", "1"),
            ("allow.raw_sockets", ""),
        ];
        assert_eq!(got, want.map(|(k, v)| (k.to_owned(), v.to_owned())));
        assert!(step_params(&[], &["pipe".to_owned()]).is_err());
    }
}
