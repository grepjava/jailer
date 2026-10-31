//! FreeBSD system operations for `jailer`: jails (`jls`, `jail`), ZFS
//! datasets/snapshots/clones (`zfs`), and mounts (`mount`, `umount`, `devfs`),
//! matching `legion-sys`.

use std::collections::{BTreeMap, BTreeSet};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{command}: {message}")]
    Failed { command: String, message: String },
    #[error("running {command}: {source}")]
    Spawn {
        command: String,
        source: std::io::Error,
    },
    #[error("{command}: unexpected output: {message}")]
    Parse { command: String, message: String },
    #[error("{0} not found")]
    NotFound(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jail {
    pub jid: u32,
    pub name: String,
    pub vnet: String,
    pub children_max: u32,
    pub children_cur: u32,
    pub parent: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dataset {
    pub name: String,
    pub mountpoint: Option<String>,
    pub quota: Option<u64>,
}

pub trait Sys: Send + Sync {
    fn kld_load(&self, module: &str) -> Result<()>;

    // Jails.
    fn jails(&self) -> Result<Vec<Jail>>;
    fn jail_set(&self, jail: &str, params: &[(&str, &str)]) -> Result<()>;
    fn jail_create(&self, params: &[(&str, &str)]) -> Result<u32>;
    fn jail_remove(&self, jail: &str) -> Result<()>;

    // ZFS.
    fn zfs_available(&self) -> bool;
    fn zfs_list(&self, root: &str) -> Result<Vec<Dataset>>;
    fn zfs_create(&self, name: &str, props: &[(&str, &str)]) -> Result<()>;
    fn zfs_set(&self, name: &str, prop: &str, value: &str) -> Result<()>;
    fn zfs_snapshot(&self, snapshot: &str) -> Result<()>;
    fn zfs_snapshots(&self, dataset: &str) -> Result<Vec<String>>;
    fn zfs_clone(&self, snapshot: &str, dataset: &str, props: &[(&str, &str)]) -> Result<()>;
    fn zfs_destroy(&self, name: &str, recursive: bool) -> Result<()>;
    fn zfs_mount(&self, dataset: &str) -> Result<()>;

    // Mounts.
    fn mount_tmpfs(&self, path: &str, size: Option<u64>, mode: u32) -> Result<()>;
    fn mount_nullfs(&self, source: &str, target: &str, read_only: bool) -> Result<()>;
    fn mount_devfs(&self, target: &str, ruleset: u32) -> Result<()>;
    fn devfs_link(&self, dev: &str, name: &str, target: &str) -> Result<()>;
    fn mount_pseudo(&self, fstype: &str, target: &str, options: &str) -> Result<()>;
    fn unmount(&self, path: &str) -> Result<()>;
    fn mounts(&self, prefix: &str) -> Result<Vec<String>>;
}

pub trait Runner: Send + Sync {
    fn run(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&str>,
    ) -> std::io::Result<CommandOutput>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Host;

impl Runner for Host {
    fn run(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&str>,
    ) -> std::io::Result<CommandOutput> {
        use std::io::Write;
        let mut child = Command::new(program)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .expect("piped stdin")
                .write_all(input.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        Ok(CommandOutput {
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Shell<R = Host> {
    runner: R,
}

impl Shell<Host> {
    pub fn new() -> Self {
        Shell { runner: Host }
    }
}

impl<R: Runner> Shell<R> {
    pub fn with_runner(runner: R) -> Self {
        Shell { runner }
    }

    fn output(&self, program: &str, args: &[String], stdin: Option<&str>) -> Result<CommandOutput> {
        let command = describe(program, args);
        tracing::debug!(%command, "run");
        self.runner
            .run(program, args, stdin)
            .map_err(|source| Error::Spawn { command, source })
    }

    fn run(&self, program: &str, args: &[String]) -> Result<String> {
        let out = self.output(program, args, None)?;
        if out.success {
            Ok(out.stdout)
        } else {
            Err(failed(program, args, &out))
        }
    }
}

fn gone(stderr: &str) -> bool {
    stderr.contains("not found") || stderr.contains("is dying")
}

fn describe(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

fn failed(program: &str, args: &[String], out: &CommandOutput) -> Error {
    let message = out.stderr.trim();
    Error::Failed {
        command: describe(program, args),
        message: if message.is_empty() {
            "failed with no message".to_owned()
        } else {
            message.to_owned()
        },
    }
}

fn args<const N: usize>(a: [&str; N]) -> Vec<String> {
    a.iter().map(|s| (*s).to_owned()).collect()
}

#[derive(Deserialize)]
struct JlsOutput {
    #[serde(rename = "jail-information")]
    info: JlsInfo,
}

#[derive(Deserialize)]
struct JlsInfo {
    #[serde(default)]
    jail: Vec<JlsJail>,
}

#[derive(Deserialize)]
struct JlsJail {
    jid: String,
    name: String,
    vnet: String,
    #[serde(rename = "children.max")]
    children_max: String,
    #[serde(rename = "children.cur")]
    children_cur: String,
    parent: String,
}

impl<R: Runner> Sys for Shell<R> {
    fn kld_load(&self, module: &str) -> Result<()> {
        if self.run("kldstat", &args(["-q", "-m", module])).is_ok() {
            return Ok(());
        }
        self.run("kldload", &args(["-n", module])).map(drop)
    }

    fn jails(&self) -> Result<Vec<Jail>> {
        let a = args([
            "--libxo=json",
            "-n",
            "jid",
            "name",
            "vnet",
            "children.max",
            "children.cur",
            "parent",
        ]);
        let out = self.run("jls", &a)?;
        parse_jls(&out).map_err(|message| Error::Parse {
            command: describe("jls", &a),
            message,
        })
    }

    fn jail_set(&self, jail: &str, params: &[(&str, &str)]) -> Result<()> {
        let target = if jail.contains('.') {
            let jid = self.run("jls", &args(["-j", jail, "jid"]))?;
            format!("jid={}", jid.trim())
        } else {
            format!("name={jail}")
        };
        let mut a = vec!["-m".to_owned(), target];
        a.extend(params.iter().map(|(k, v)| format!("{k}={v}")));
        self.run("jail", &a).map(drop)
    }

    fn jail_create(&self, params: &[(&str, &str)]) -> Result<u32> {
        let mut a = args(["-i", "-c"]);
        a.extend(params.iter().map(|(k, v)| {
            if v.is_empty() {
                (*k).to_owned()
            } else {
                format!("{k}={v}")
            }
        }));
        let out = self.run("jail", &a)?;
        out.lines()
            .next()
            .unwrap_or("")
            .trim()
            .parse()
            .map_err(|_| Error::Parse {
                command: describe("jail", &a),
                message: format!("not a jid: {out:?}"),
            })
    }

    fn jail_remove(&self, jail: &str) -> Result<()> {
        let a = args(["-j", jail, "jid"]);
        let out = self.output("jls", &a, None)?;
        if !out.success {
            if gone(&out.stderr) {
                return Err(Error::NotFound(format!("jail {jail}")));
            }
            return Err(failed("jls", &a, &out));
        }
        self.run("jail", &args(["-r", out.stdout.trim()])).map(drop)
    }

    fn zfs_available(&self) -> bool {
        self.output("zfs", &args(["list", "-H", "-d", "0"]), None)
            .is_ok_and(|o| o.success && !o.stdout.trim().is_empty())
    }

    fn zfs_list(&self, root: &str) -> Result<Vec<Dataset>> {
        let a = args([
            "list",
            "-H",
            "-p",
            "-r",
            "-t",
            "filesystem",
            "-o",
            "name,mountpoint,quota",
            root,
        ]);
        let out = self.output("zfs", &a, None)?;
        if !out.success {
            if out.stderr.contains("dataset does not exist") {
                return Ok(Vec::new());
            }
            return Err(failed("zfs", &a, &out));
        }
        out.stdout
            .lines()
            .filter(|l| !l.is_empty())
            .map(|line| {
                parse_dataset(line).ok_or_else(|| Error::Parse {
                    command: describe("zfs", &a),
                    message: format!("bad line {line:?}"),
                })
            })
            .collect()
    }

    fn zfs_create(&self, name: &str, props: &[(&str, &str)]) -> Result<()> {
        let mut a = args(["create", "-p"]);
        for (k, v) in props {
            a.extend(["-o".to_owned(), format!("{k}={v}")]);
        }
        a.push(name.to_owned());
        self.run("zfs", &a).map(drop)
    }

    fn zfs_set(&self, name: &str, prop: &str, value: &str) -> Result<()> {
        self.run(
            "zfs",
            &["set".to_owned(), format!("{prop}={value}"), name.to_owned()],
        )
        .map(drop)
    }

    fn zfs_snapshot(&self, snapshot: &str) -> Result<()> {
        self.run("zfs", &args(["snapshot", snapshot])).map(drop)
    }

    fn zfs_snapshots(&self, dataset: &str) -> Result<Vec<String>> {
        let a = args([
            "list",
            "-H",
            "-t",
            "snapshot",
            "-o",
            "name",
            "-s",
            "createtxg",
            "-d",
            "1",
            dataset,
        ]);
        let out = self.output("zfs", &a, None)?;
        if !out.success {
            if out.stderr.contains("dataset does not exist") {
                return Ok(Vec::new());
            }
            return Err(failed("zfs", &a, &out));
        }
        Ok(out
            .stdout
            .lines()
            .filter_map(|l| l.split_once('@'))
            .map(|(_, name)| name.to_owned())
            .collect())
    }

    fn zfs_clone(&self, snapshot: &str, dataset: &str, props: &[(&str, &str)]) -> Result<()> {
        let mut a = args(["clone"]);
        for (k, v) in props {
            a.extend(["-o".to_owned(), format!("{k}={v}")]);
        }
        a.extend([snapshot.to_owned(), dataset.to_owned()]);
        self.run("zfs", &a).map(drop)
    }

    fn zfs_destroy(&self, name: &str, recursive: bool) -> Result<()> {
        let a = if recursive {
            args(["destroy", "-r", name])
        } else {
            args(["destroy", name])
        };
        self.run("zfs", &a).map(drop)
    }

    fn zfs_mount(&self, dataset: &str) -> Result<()> {
        let mounted = self.run(
            "zfs",
            &args(["get", "-H", "-o", "value", "mounted", dataset]),
        )?;
        if mounted.trim() == "yes" {
            return Ok(());
        }
        self.run("zfs", &args(["mount", dataset])).map(drop)
    }

    fn mount_tmpfs(&self, path: &str, size: Option<u64>, mode: u32) -> Result<()> {
        let mut opts = format!("mode={mode:04o}");
        if let Some(size) = size {
            opts += &format!(",size={size}");
        }
        self.run("mount", &args(["-t", "tmpfs", "-o", &opts, "tmpfs", path]))
            .map(drop)
    }

    fn mount_nullfs(&self, source: &str, target: &str, read_only: bool) -> Result<()> {
        let opts = if read_only { "ro" } else { "rw" };
        self.run("mount", &args(["-t", "nullfs", "-o", opts, source, target]))
            .map(drop)
    }

    fn mount_devfs(&self, target: &str, ruleset: u32) -> Result<()> {
        self.run("mount", &args(["-t", "devfs", "devfs", target]))?;
        let set = ruleset.to_string();
        let applied = self
            .run("devfs", &args(["-m", target, "ruleset", &set]))
            .and_then(|_| self.run("devfs", &args(["-m", target, "rule", "applyset"])));
        if let Err(e) = applied {
            let _ = self.run("umount", &args(["-f", target]));
            return Err(e);
        }
        Ok(())
    }

    fn devfs_link(&self, dev: &str, name: &str, target: &str) -> Result<()> {
        let link = format!("{}/{name}", dev.trim_end_matches('/'));
        self.run("ln", &args(["-s", target, &link]))?;
        self.run(
            "devfs",
            &args(["-m", dev, "rule", "apply", "path", name, "unhide"]),
        )
        .map(drop)
    }

    fn mount_pseudo(&self, fstype: &str, target: &str, options: &str) -> Result<()> {
        let mut a = vec!["-t", fstype];
        if !options.is_empty() {
            a.extend(["-o", options]);
        }
        a.extend([fstype, target]);
        let a: Vec<String> = a.iter().map(|s| (*s).to_owned()).collect();
        self.run("mount", &a).map(drop)
    }

    fn unmount(&self, path: &str) -> Result<()> {
        self.run("umount", &args(["-f", path])).map(drop)
    }

    fn mounts(&self, prefix: &str) -> Result<Vec<String>> {
        let out = self.run("mount", &args(["-p"]))?;
        Ok(parse_mounts(&out, prefix))
    }
}

fn parse_mounts(out: &str, prefix: &str) -> Vec<String> {
    let prefix = prefix.trim_end_matches('/');
    out.lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .map(|p| p.replace("\\040", " "))
        .filter(|p| {
            p == prefix
                || p.strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
        .collect()
}

fn parse_jls(out: &str) -> Result<Vec<Jail>, String> {
    let parsed: JlsOutput = serde_json::from_str(out).map_err(|e| e.to_string())?;
    parsed
        .info
        .jail
        .into_iter()
        .map(|j| {
            let num = |field: &str, v: &str| {
                v.parse::<u32>()
                    .map_err(|_| format!("{field} {v:?} of jail {:?} is not a number", j.name))
            };
            Ok(Jail {
                jid: num("jid", &j.jid)?,
                children_max: num("children.max", &j.children_max)?,
                children_cur: num("children.cur", &j.children_cur)?,
                parent: num("parent", &j.parent)?,
                name: j.name,
                vnet: j.vnet,
            })
        })
        .collect()
}

fn parse_dataset(line: &str) -> Option<Dataset> {
    let mut cols = line.split('\t');
    let name = cols.next()?.to_owned();
    let mountpoint = match cols.next()? {
        "-" | "none" | "legacy" => None,
        m => Some(m.to_owned()),
    };
    let quota = match cols.next()? {
        "0" | "-" | "none" => None,
        q => Some(q.parse().ok()?),
    };
    Some(Dataset {
        name,
        mountpoint,
        quota,
    })
}

/// In-memory `Sys` implementation for unit tests on any host OS.
#[derive(Default)]
pub struct FakeSys {
    inner: Mutex<FakeState>,
    zfs_enabled: bool,
}

#[derive(Default)]
struct FakeState {
    next_jid: u32,
    jails: BTreeMap<String, Jail>,
    datasets: BTreeMap<String, FakeDataset>,
    mounts: BTreeSet<String>,
    modules: BTreeSet<String>,
}

#[derive(Clone, Default)]
struct FakeDataset {
    mountpoint: Option<String>,
    quota: Option<u64>,
    snapshots: Vec<String>,
}

impl FakeSys {
    pub fn new(zfs_enabled: bool) -> Self {
        Self {
            inner: Mutex::new(FakeState::default()),
            zfs_enabled,
        }
    }
}

impl Sys for FakeSys {
    fn kld_load(&self, module: &str) -> Result<()> {
        self.inner.lock().unwrap().modules.insert(module.to_owned());
        Ok(())
    }

    fn jails(&self) -> Result<Vec<Jail>> {
        Ok(self.inner.lock().unwrap().jails.values().cloned().collect())
    }

    fn jail_set(&self, jail: &str, _params: &[(&str, &str)]) -> Result<()> {
        let st = self.inner.lock().unwrap();
        if !st.jails.contains_key(jail) {
            return Err(Error::NotFound(format!("jail {jail}")));
        }
        Ok(())
    }

    fn jail_create(&self, params: &[(&str, &str)]) -> Result<u32> {
        let mut st = self.inner.lock().unwrap();
        st.next_jid += 1;
        let jid = st.next_jid;
        let name = params
            .iter()
            .find(|(k, _)| *k == "name")
            .map(|(_, v)| (*v).to_owned())
            .unwrap_or_else(|| jid.to_string());
        let vnet = if params.iter().any(|(k, _)| *k == "vnet") {
            "new".to_owned()
        } else {
            "inherit".to_owned()
        };
        st.jails.insert(
            name.clone(),
            Jail {
                jid,
                name,
                vnet,
                children_max: 0,
                children_cur: 0,
                parent: 0,
            },
        );
        Ok(jid)
    }

    fn jail_remove(&self, jail: &str) -> Result<()> {
        let mut st = self.inner.lock().unwrap();
        if st.jails.remove(jail).is_none() {
            return Err(Error::NotFound(format!("jail {jail}")));
        }
        Ok(())
    }

    fn zfs_available(&self) -> bool {
        self.zfs_enabled
    }

    fn zfs_list(&self, root: &str) -> Result<Vec<Dataset>> {
        let st = self.inner.lock().unwrap();
        let prefix = format!("{root}/");
        Ok(st
            .datasets
            .iter()
            .filter(|(k, _)| *k == root || k.starts_with(&prefix))
            .map(|(k, d)| Dataset {
                name: k.clone(),
                mountpoint: d.mountpoint.clone(),
                quota: d.quota,
            })
            .collect())
    }

    fn zfs_create(&self, name: &str, props: &[(&str, &str)]) -> Result<()> {
        let mut st = self.inner.lock().unwrap();
        let mp = props
            .iter()
            .find(|(k, _)| *k == "mountpoint")
            .map(|(_, v)| (*v).to_owned())
            .filter(|v| v != "none" && v != "-");
        st.datasets
            .entry(name.to_owned())
            .or_insert_with(|| FakeDataset {
                mountpoint: mp,
                quota: None,
                snapshots: Vec::new(),
            });
        Ok(())
    }

    fn zfs_set(&self, name: &str, prop: &str, value: &str) -> Result<()> {
        let mut st = self.inner.lock().unwrap();
        if let Some(ds) = st.datasets.get_mut(name)
            && prop == "mountpoint"
        {
            ds.mountpoint = if value == "none" || value == "-" {
                None
            } else {
                Some(value.to_owned())
            };
        }
        Ok(())
    }

    fn zfs_snapshot(&self, snapshot: &str) -> Result<()> {
        let (ds, snap) = snapshot.split_once('@').ok_or_else(|| Error::Failed {
            command: format!("zfs snapshot {snapshot}"),
            message: "missing @".to_owned(),
        })?;
        let mut st = self.inner.lock().unwrap();
        let entry = st
            .datasets
            .get_mut(ds)
            .ok_or_else(|| Error::NotFound(format!("dataset {ds}")))?;
        if !entry.snapshots.iter().any(|s| s == snap) {
            entry.snapshots.push(snap.to_owned());
        }
        Ok(())
    }

    fn zfs_snapshots(&self, dataset: &str) -> Result<Vec<String>> {
        let st = self.inner.lock().unwrap();
        Ok(st
            .datasets
            .get(dataset)
            .map(|d| d.snapshots.clone())
            .unwrap_or_default())
    }

    fn zfs_clone(&self, snapshot: &str, dataset: &str, props: &[(&str, &str)]) -> Result<()> {
        let (parent_ds, _) = snapshot.split_once('@').ok_or_else(|| Error::Failed {
            command: format!("zfs clone {snapshot}"),
            message: "missing @".to_owned(),
        })?;
        let parent_mp = {
            let st = self.inner.lock().unwrap();
            st.datasets
                .get(parent_ds)
                .and_then(|d| d.mountpoint.clone())
        };
        let mp = props
            .iter()
            .find(|(k, _)| *k == "mountpoint")
            .map(|(_, v)| (*v).to_owned())
            .filter(|v| v != "none" && v != "-");
        if let (Some(src), Some(dst)) = (&parent_mp, &mp)
            && std::path::Path::new(src).exists()
        {
            let _ = crate::layer::copy_tree(std::path::Path::new(src), std::path::Path::new(dst));
        }
        let mut st = self.inner.lock().unwrap();
        st.datasets.insert(
            dataset.to_owned(),
            FakeDataset {
                mountpoint: mp,
                quota: None,
                snapshots: Vec::new(),
            },
        );
        Ok(())
    }

    fn zfs_destroy(&self, name: &str, recursive: bool) -> Result<()> {
        let mut st = self.inner.lock().unwrap();
        if let Some((ds, snap)) = name.split_once('@') {
            if let Some(d) = st.datasets.get_mut(ds) {
                d.snapshots.retain(|s| s != snap);
            }
            return Ok(());
        }
        let prefix = format!("{name}/");
        if recursive {
            st.datasets
                .retain(|k, _| k != name && !k.starts_with(&prefix));
        } else {
            st.datasets.remove(name);
        }
        Ok(())
    }

    fn zfs_mount(&self, _dataset: &str) -> Result<()> {
        Ok(())
    }

    fn mount_tmpfs(&self, path: &str, _size: Option<u64>, _mode: u32) -> Result<()> {
        self.inner.lock().unwrap().mounts.insert(path.to_owned());
        Ok(())
    }

    fn mount_nullfs(&self, _source: &str, target: &str, _read_only: bool) -> Result<()> {
        self.inner.lock().unwrap().mounts.insert(target.to_owned());
        Ok(())
    }

    fn mount_devfs(&self, target: &str, _ruleset: u32) -> Result<()> {
        self.inner.lock().unwrap().mounts.insert(target.to_owned());
        Ok(())
    }

    fn devfs_link(&self, _dev: &str, _name: &str, _target: &str) -> Result<()> {
        Ok(())
    }

    fn mount_pseudo(&self, _fstype: &str, target: &str, _options: &str) -> Result<()> {
        self.inner.lock().unwrap().mounts.insert(target.to_owned());
        Ok(())
    }

    fn unmount(&self, path: &str) -> Result<()> {
        self.inner.lock().unwrap().mounts.remove(path);
        Ok(())
    }

    fn mounts(&self, prefix: &str) -> Result<Vec<String>> {
        let prefix = prefix.trim_end_matches('/');
        let st = self.inner.lock().unwrap();
        Ok(st
            .mounts
            .iter()
            .filter(|p| {
                *p == prefix
                    || p.strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('\\'))
            })
            .cloned()
            .collect())
    }
}
