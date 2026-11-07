//! `jailer doctor`: what this host lets jailer do. The checks are Legion's,
//! in `legion_sys::check`, and change nothing; what each one blocks is
//! jailer's own to say, as a host with no pf builds images well enough.

use legion_sys::Sys;
use legion_sys::check::{self, Finding, State};
use serde::Serialize;

/// What a host may or may not be fit for.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    /// Builds with `RUN` steps
    Build,
    /// `jailer run` on the host's network
    Run,
    /// `--vnet`, `--network bridge` and published ports
    Vnet,
    /// `-m`, `--cpus` and the like
    Limits,
    /// `-v` and `RUN --mount`
    Mounts,
    /// Linux images
    Linux,
}

impl Operation {
    pub const ALL: [Operation; 6] = [
        Operation::Build,
        Operation::Run,
        Operation::Vnet,
        Operation::Limits,
        Operation::Mounts,
        Operation::Linux,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Ready,
    /// A check it needs could not be read: not known to work.
    Unknown,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    #[serde(flatten)]
    pub finding: Finding,
    /// What cannot work unless this is met. Empty for what jailer sees to
    /// itself, which is reported all the same.
    pub required_for: Vec<Operation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationStatus {
    pub name: Operation,
    pub status: Status,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub operations: Vec<OperationStatus>,
    pub checks: Vec<Entry>,
}

impl Report {
    /// Whether all that was asked about is known to work.
    pub fn passed(&self) -> bool {
        self.operations.iter().all(|o| o.status == Status::Ready)
    }
}

/// What the checks depend on beyond `Sys`.
pub struct Host<'a> {
    pub root: bool,
    /// The ZFS root in use, none with plain directories.
    pub zfs_root: Option<&'a str>,
    /// Why the pod network's addresses can't be used, if so.
    pub subnet: Result<(), String>,
}

fn finding(id: &str, state: State, detail: String, remedy: Option<String>) -> Finding {
    Finding {
        id: id.to_owned(),
        state,
        detail,
        remedy,
    }
}

fn root(yes: bool) -> Finding {
    if yes {
        finding("root", State::Met, "running as root".to_owned(), None)
    } else {
        finding(
            "root",
            State::Unmet,
            "not running as root".to_owned(),
            Some("run jailer with sudo or doas".to_owned()),
        )
    }
}

fn subnet(result: &Result<(), String>) -> Finding {
    match result {
        Ok(()) => finding(
            "subnet",
            State::Met,
            "no other network has the pod addresses".to_owned(),
            None,
        ),
        Err(e) => finding(
            "subnet",
            State::Unmet,
            e.clone(),
            Some(
                "remove that network, choose another with --pod-subnet, or use --network none"
                    .to_owned(),
            ),
        ),
    }
}

/// Runs the checks `operations` need, and no others.
pub fn examine(sys: &dyn Sys, host: &Host, operations: &[Operation]) -> Report {
    use Operation::*;
    let mut checks: Vec<Entry> = Vec::new();
    let mut add = |needed_by: &[Operation], run: &mut dyn FnMut() -> Finding| {
        let required_for: Vec<_> = needed_by
            .iter()
            .copied()
            .filter(|o| operations.contains(o))
            .collect();
        if !required_for.is_empty() {
            checks.push(Entry {
                finding: run(),
                required_for,
            });
        }
    };

    add(&Operation::ALL, &mut || root(host.root));
    if let Some(dataset) = host.zfs_root {
        // jailer makes the dataset itself, on a pool that must be there.
        let pool = dataset.split('/').next().unwrap_or(dataset);
        add(&Operation::ALL, &mut || check::zfs_root(sys, pool));
    }
    add(&[Limits], &mut || check::racct(sys));
    add(&[Mounts], &mut || check::module(sys, "nullfs"));
    add(&[Mounts, Linux], &mut || check::module(sys, "tmpfs"));
    for name in check::LINUX_MODULES.iter().filter(|m| **m != "tmpfs") {
        add(&[Linux], &mut || check::module(sys, name));
    }
    for name in ["pf", "if_bridge", "if_epair"] {
        add(&[Vnet], &mut || check::module(sys, name));
    }
    add(&[Vnet], &mut || {
        check::pf_anchors(sys, "jailer/*", crate::net::HOOKS)
    });
    add(&[Vnet], &mut || subnet(&host.subnet));

    // `run --vnet` turns this on itself; off, it is only worth knowing.
    if operations.contains(&Vnet) {
        checks.push(Entry {
            finding: check::forwarding(sys),
            required_for: Vec::new(),
        });
    }

    let status = |operation: Operation| {
        let states = || {
            checks
                .iter()
                .filter(|c| c.required_for.contains(&operation))
                .map(|c| c.finding.state)
        };
        if states().any(|s| matches!(s, State::Unmet | State::Unsupported)) {
            Status::Blocked
        } else if states().any(|s| s == State::Unknown) {
            Status::Unknown
        } else {
            Status::Ready
        }
    };
    let operations = operations
        .iter()
        .map(|&name| OperationStatus {
            name,
            status: status(name),
        })
        .collect();
    Report { operations, checks }
}

fn state_name(state: State) -> &'static str {
    match state {
        State::Met => "ok",
        State::Unmet => "unmet",
        State::Unknown => "unknown",
        State::Unsupported => "unsupported",
    }
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Build => "build",
        Operation::Run => "run",
        Operation::Vnet => "vnet",
        Operation::Limits => "limits",
        Operation::Mounts => "mounts",
        Operation::Linux => "linux",
    }
}

/// The report as `jailer doctor` prints it.
pub fn text(report: &Report) -> String {
    let mut out = String::new();
    for o in &report.operations {
        let status = match o.status {
            Status::Ready => "ready",
            Status::Unknown => "unknown",
            Status::Blocked => "blocked",
        };
        out.push_str(&format!("{:<8}{status}\n", operation_name(o.name)));
    }
    out.push('\n');
    let width = report
        .checks
        .iter()
        .map(|c| c.finding.id.len())
        .max()
        .unwrap_or(0);
    for c in &report.checks {
        let f = &c.finding;
        out.push_str(&format!(
            "{:<12}{:<width$}  {}\n",
            state_name(f.state),
            f.id,
            f.detail
        ));
        if f.state != State::Met {
            if let Some(remedy) = &f.remedy {
                out.push_str(&format!("{:12}fix: {remedy}\n", ""));
            }
            let needed: Vec<_> = c.required_for.iter().map(|&o| operation_name(o)).collect();
            out.push_str(&format!(
                "{:12}{}\n",
                "",
                if needed.is_empty() {
                    "optional: jailer sees to it when it can".to_owned()
                } else {
                    format!("needed for: {}", needed.join(", "))
                }
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use Operation::*;
    use legion_sys::FakeSys;

    const CALLED: &str =
        "nat-anchor \"jailer/*\" all\nrdr-anchor \"jailer/*\" all\nanchor \"jailer/*\" all\n";

    fn host() -> Host<'static> {
        Host {
            root: true,
            zfs_root: None,
            subnet: Ok(()),
        }
    }

    fn fit() -> FakeSys {
        let sys = FakeSys::new();
        sys.set_main_rules(CALLED);
        sys.sysctl_set("kern.racct.enable", "1").unwrap();
        sys
    }

    fn status(report: &Report, operation: Operation) -> Status {
        report
            .operations
            .iter()
            .find(|o| o.name == operation)
            .unwrap()
            .status
    }

    fn ids(report: &Report) -> Vec<&str> {
        report
            .checks
            .iter()
            .map(|c| c.finding.id.as_str())
            .collect()
    }

    #[test]
    fn a_fit_host_passes_and_each_check_comes_once() {
        let report = examine(&fit(), &host(), &Operation::ALL);
        assert!(report.passed(), "{}", text(&report));
        let mut seen = ids(&report);
        let all = seen.len();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), all, "{seen:?}");
    }

    #[test]
    fn what_blocks_one_operation_leaves_the_others() {
        let sys = fit();
        sys.set_main_rules("");
        sys.sysctl_set("kern.racct.enable", "0").unwrap();
        let report = examine(&sys, &host(), &Operation::ALL);
        assert!(!report.passed());
        assert_eq!(status(&report, Vnet), Status::Blocked);
        assert_eq!(status(&report, Limits), Status::Blocked);
        assert_eq!(status(&report, Build), Status::Ready);
        assert_eq!(status(&report, Run), Status::Ready);

        // Asked only of what is fine, the host passes.
        let report = examine(&sys, &host(), &[Build, Run]);
        assert!(report.passed(), "{}", text(&report));
        assert_eq!(ids(&report), ["root"]);
    }

    #[test]
    fn a_check_that_could_not_be_read_is_not_a_pass() {
        let sys = fit();
        sys.fail_next("pfctl -sn");
        let report = examine(&sys, &host(), &[Vnet]);
        assert_eq!(status(&report, Vnet), Status::Unknown);
        assert!(!report.passed());
    }

    #[test]
    fn an_ordinary_user_is_blocked_by_that_and_not_told_pf_is_wrong() {
        let sys = fit();
        sys.fail_next("pfctl -sn");
        let host = Host {
            root: false,
            ..host()
        };
        let report = examine(&sys, &host, &[Vnet]);
        assert_eq!(status(&report, Vnet), Status::Blocked);
        let pf = report
            .checks
            .iter()
            .find(|c| c.finding.id == "pf.anchors")
            .unwrap();
        assert_eq!(pf.finding.state, State::Unknown);
        assert!(pf.finding.detail.contains("needs root"), "{pf:?}");
    }

    #[test]
    fn forwarding_off_blocks_nothing_as_a_run_turns_it_on() {
        let sys = fit();
        sys.sysctl_set("net.inet.ip.forwarding", "0").unwrap();
        let report = examine(&sys, &host(), &[Vnet]);
        assert_eq!(status(&report, Vnet), Status::Ready);
        assert!(text(&report).contains("optional"));
    }

    #[test]
    fn the_pool_is_what_must_be_there_as_jailer_makes_its_dataset() {
        let sys = fit();
        sys.zfs_create("tank", &[]).unwrap();
        let on = |zfs_root| Host { zfs_root, ..host() };
        let report = examine(&sys, &on(Some("tank/jailer")), &[Build]);
        assert_eq!(status(&report, Build), Status::Ready, "{}", text(&report));
        let report = examine(&sys, &on(Some("gone/jailer")), &[Build]);
        assert_eq!(status(&report, Build), Status::Blocked);
        // With plain directories, ZFS is not asked about at all.
        assert!(!ids(&examine(&sys, &host(), &[Build])).contains(&"zfs.root"));
    }

    #[test]
    fn a_module_this_host_lacks_blocks_what_needs_it() {
        let sys = fit();
        sys.remove_module("linprocfs");
        let report = examine(&sys, &host(), &[Linux, Mounts]);
        assert_eq!(status(&report, Linux), Status::Blocked);
        assert_eq!(status(&report, Mounts), Status::Ready);
    }

    #[test]
    fn the_pod_network_taken_blocks_vnet_only() {
        let host = Host {
            subnet: Err("routed to em1".to_owned()),
            ..host()
        };
        let report = examine(&fit(), &host, &[Vnet, Run]);
        assert_eq!(status(&report, Vnet), Status::Blocked);
        assert_eq!(status(&report, Run), Status::Ready);
    }

    #[test]
    fn json_holds_the_ids_states_and_what_each_blocks() {
        let sys = fit();
        sys.sysctl_set("kern.racct.enable", "0").unwrap();
        let report = examine(&sys, &host(), &[Limits]);
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["operations"][0]["name"], "limits");
        assert_eq!(v["operations"][0]["status"], "blocked");
        let racct = v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "racct")
            .unwrap();
        assert_eq!(racct["state"], "unmet");
        assert_eq!(racct["required_for"][0], "limits");
        assert!(racct["remedy"].as_str().unwrap().contains("loader.conf"));
    }
}
