//! Local jail runtime for `jailer run`, `jailer exec`, `jailer ps`,
//! `jailer logs`, `jailer stop`, `jailer rm`, and `jailer build` `RUN` steps.
//! Matches `legion-jail`'s runtime behavior: ZFS clone (or directory copy)
//! rootfs, `devfs` ruleset 4, `nullfs` volume mounts, Linux ABI mounts,
//! `/etc/passwd` + `/etc/group` user resolution, and `enforce_statfs=2`.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::state::{self, EXIT, Exit, LOG, Mount, RECORD, RUN, Record, Run, SHIM_LOG};
use crate::store::{StorageMode, Store};
use crate::sys::Sys;
use crate::{Error, log};

/// Kernel modules Linux images need: the ABI and the file systems mounted
/// for them (`/proc`, `/sys`, `/dev/fd`, `/dev/shm`).
pub const LINUX_MODULES: [&str; 5] = ["linux64", "linprocfs", "linsysfs", "fdescfs", "tmpfs"];

const LINUX_MOUNTS: [(&str, &str, &str); 4] = [
    ("linprocfs", "/proc", ""),
    ("linsysfs", "/sys", ""),
    ("fdescfs", "/dev/fd", "linrdlnk"),
    ("tmpfs", SHM, ""),
];

const SHM: &str = "/.legion-shm";
pub const DEVFS_RULESET: u32 = 4;

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub state_dir: PathBuf,
    pub dataset: Option<String>,
    pub shim: Vec<OsString>,
}

#[derive(Debug, Clone, Default)]
pub struct RunSpec {
    pub name: Option<String>,
    pub image: String,
    pub entrypoint: Vec<String>,
    pub command: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub user: Option<String>,
    pub work_dir: Option<String>,
    pub hostname: Option<String>,
    pub mounts: Vec<Mount>,
    pub params: Vec<(String, String)>,
    pub stop_timeout: Option<u64>,
    pub vnet: bool,
    pub allow_mlock: bool,
    pub sysv: Vec<String>,
    pub linux: bool,
    pub rm: bool,
    pub detach: bool,
    pub interactive: bool,
    pub tty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Created,
    Running(Run),
    Exited(Exit),
}

impl Status {
    pub fn name(&self) -> &'static str {
        match self {
            Status::Created => "created",
            Status::Running(_) => "running",
            Status::Exited(_) => "exited",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ContainerSummary {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: Status,
    pub created: u64,
}

pub struct JailRuntime {
    sys: Arc<dyn Sys>,
    images: Arc<Store>,
    dir: PathBuf,
    dataset: Option<String>,
    shim: Vec<OsString>,
    boot: u64,
}

fn new_id() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("random bytes");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(unix)]
fn alive(pid: u32) -> bool {
    pid != 0 && unsafe { libc::kill(pid as libc::pid_t, 0) } == 0
}

#[cfg(not(unix))]
fn alive(_: u32) -> bool {
    false
}

/// `dest` (a path in the container) under `root`, made if missing (a file
/// if `file`) without following links: a link in the image must not send a
/// mount outside its root.
pub fn target(root: &Path, dest: &str, file: bool) -> Result<PathBuf, Error> {
    let mut path = root.to_path_buf();
    let parts: Vec<_> = Path::new(dest)
        .components()
        .filter(|c| !matches!(c, Component::RootDir | Component::CurDir))
        .collect();
    for (i, c) in parts.iter().enumerate() {
        let Component::Normal(name) = c else {
            return Err(Error::Runtime(format!(
                "mount target {dest}: no `..` allowed"
            )));
        };
        path.push(name);
        let last = i + 1 == parts.len();
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(Error::Runtime(format!(
                    "mount target {dest} goes through a link"
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if last && file {
                    std::fs::File::create(&path)?;
                } else {
                    std::fs::create_dir(&path)?;
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(path)
}

impl JailRuntime {
    pub fn new(
        sys: Arc<dyn Sys>,
        images: Arc<Store>,
        config: RuntimeConfig,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(&config.state_dir)?;
        Ok(Self {
            sys,
            images,
            dir: config.state_dir,
            dataset: config.dataset,
            shim: config.shim,
            boot: state::boot_time(),
        })
    }

    pub fn container_dir(&self, id: &str) -> PathBuf {
        self.dir.join(id)
    }

    /// Resolves a container by ID, ID prefix, or name.
    pub fn record(&self, id_or_name: &str) -> Result<Record, Error> {
        let all = records(&self.dir)?;
        if let Some(r) = all
            .iter()
            .find(|r| r.id == id_or_name || r.name == id_or_name)
        {
            return Ok(r.clone());
        }
        if id_or_name.len() >= 4 {
            let matches: Vec<_> = all
                .into_iter()
                .filter(|r| r.id.starts_with(id_or_name))
                .collect();
            if matches.len() == 1 {
                return Ok(matches.into_iter().next().unwrap());
            }
        }
        Err(Error::NotFound(format!("no such container {id_or_name:?}")))
    }

    pub fn status(&self, rec: &Record) -> Result<Status, Error> {
        let jails = jail_names(&*self.sys)?;
        status(&self.dir, rec, self.boot, &jails)
    }

    fn shim_command(&self, args: &[&std::ffi::OsStr]) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.shim[0]);
        cmd.args(&self.shim[1..]).args(args);
        cmd
    }

    fn make_record(&self, spec: &RunSpec) -> Result<Record, Error> {
        let existing = records(&self.dir)?;
        let id = new_id();
        let name = match &spec.name {
            Some(n) => {
                if existing.iter().any(|r| r.name == *n) {
                    return Err(Error::Runtime(format!(
                        "the container name {n:?} is in use"
                    )));
                }
                n.clone()
            }
            None => format!("jailer-{}", &id[..12]),
        };

        let image = self
            .images
            .find(&spec.image)?
            .ok_or_else(|| Error::NotFound(format!("{}: image not known", spec.image)))?;
        let linux = image.config.os == "linux" || spec.linux;
        if image.config.os == "linux" && !spec.linux && !self.images.runs("linux") {
            return Err(Error::Runtime(format!(
                "{} is a Linux image; pass --linux to run it through FreeBSD's Linux ABI",
                spec.image
            )));
        }

        let mut params = spec.params.clone();
        if spec.allow_mlock {
            params.push(("allow.mlock".to_owned(), "true".to_owned()));
        }
        for s in &spec.sysv {
            match s.trim() {
                "msg" | "sysvmsg" => params.push(("sysvmsg".to_owned(), "new".to_owned())),
                "sem" | "sysvsem" => params.push(("sysvsem".to_owned(), "new".to_owned())),
                "shm" | "sysvshm" => params.push(("sysvshm".to_owned(), "new".to_owned())),
                other => {
                    return Err(Error::Runtime(format!(
                        "unknown --sysv option {other:?} (expected msg, sem, or shm)"
                    )));
                }
            }
        }

        let cfg = &image.config.config;
        let argv: Vec<String> = if !spec.entrypoint.is_empty() {
            spec.entrypoint
                .iter()
                .chain(&spec.command)
                .cloned()
                .collect()
        } else if !spec.command.is_empty() {
            cfg.entrypoint
                .iter()
                .chain(&spec.command)
                .cloned()
                .collect()
        } else {
            cfg.entrypoint.iter().chain(&cfg.cmd).cloned().collect()
        };
        if argv.is_empty() {
            return Err(Error::Runtime(format!("{}: no command to run", spec.image)));
        }

        let mut env: Vec<String> = cfg
            .env
            .iter()
            .filter(|e| {
                let k = e.split('=').next().unwrap_or("");
                !spec.env.contains_key(k)
            })
            .cloned()
            .collect();
        env.extend(spec.env.iter().map(|(k, v)| format!("{k}={v}")));
        let hostname = spec.hostname.clone().unwrap_or_else(|| name.clone());
        if !env.iter().any(|e| e.starts_with("HOSTNAME=")) {
            env.push(format!("HOSTNAME={hostname}"));
        }

        let root = self.container_dir(&id).join("root");
        let dataset = match (self.images.mode(), &self.dataset) {
            (StorageMode::Zfs(_), Some(ds)) => Some(format!("{ds}/{id}")),
            _ => None,
        };

        Ok(Record {
            id: id.clone(),
            name,
            image: image
                .references
                .first()
                .cloned()
                .unwrap_or_else(|| spec.image.clone()),
            created: state::now(),
            labels: BTreeMap::new(),
            annotations: if spec.vnet {
                BTreeMap::from([("org.freebsd.jail.vnet".to_owned(), "new".to_owned())])
            } else {
                BTreeMap::new()
            },
            parent: None,
            jail: format!("jailer_{}", &id[..12]),
            root,
            dataset,
            argv,
            env,
            user: spec
                .user
                .clone()
                .filter(|u| !u.is_empty())
                .unwrap_or_else(|| cfg.user.clone()),
            work_dir: spec
                .work_dir
                .clone()
                .filter(|w| !w.is_empty())
                .or_else(|| Some(cfg.working_dir.clone()).filter(|w| !w.is_empty()))
                .unwrap_or_else(|| "/".to_owned()),
            hostname,
            mounts: spec.mounts.clone(),
            params,
            stop_signal: state::signal(&cfg.stop_signal).unwrap_or(15),
            stop_timeout: spec.stop_timeout.unwrap_or(10),
            linux,
        })
    }

    pub fn mount(&self, rec: &Record) -> Result<(), Error> {
        let sys = &*self.sys;
        if let Some(ds) = &rec.dataset {
            sys.zfs_mount(ds)?;
        }
        let mounted = sys.mounts(&rec.root.to_string_lossy())?;
        let is_mounted = |p: &Path| mounted.iter().any(|m| Path::new(m) == p);
        let dev = target(&rec.root, "/dev", false)?;
        let dev_was_mounted = is_mounted(&dev);
        if !dev_was_mounted {
            sys.mount_devfs(&dev.to_string_lossy(), DEVFS_RULESET)?;
        }
        if rec.linux {
            for m in LINUX_MODULES {
                let _ = sys.kld_load(m);
            }
            for (fstype, at, options) in LINUX_MOUNTS {
                let at = target(&rec.root, at, false)?;
                if is_mounted(&at) {
                    continue;
                }
                let at = at.to_string_lossy();
                match fstype {
                    "tmpfs" => sys.mount_tmpfs(&at, None, 0o1777),
                    _ => sys.mount_pseudo(fstype, &at, options),
                }?;
            }
            if !dev_was_mounted {
                sys.devfs_link(&dev.to_string_lossy(), "shm", SHM)?;
            }
        }
        for m in &rec.mounts {
            let file = std::fs::metadata(&m.source)
                .map_err(|e| Error::Runtime(format!("{}: {e}", m.source)))?
                .is_file();
            let at = target(&rec.root, &m.destination, file)?;
            if !is_mounted(&at) {
                sys.mount_nullfs(&m.source, &at.to_string_lossy(), m.read_only)?;
            }
        }
        // Provide /etc/resolv.conf from host if the image doesn't have one so
        // networked processes inside the test jail can resolve DNS names.
        if let Ok(Some(resolv)) = target(&rec.root, "/etc/resolv.conf", true).map(Some)
            && std::fs::metadata(&resolv).map_or(true, |m| m.len() == 0)
            && Path::new("/etc/resolv.conf").exists()
        {
            let _ = std::fs::copy("/etc/resolv.conf", &resolv);
        }
        Ok(())
    }

    pub fn unmount(&self, rec: &Record) -> Result<(), Error> {
        let mut mounted = self.sys.mounts(&rec.root.to_string_lossy())?;
        mounted.sort_by_key(|m| std::cmp::Reverse(m.len()));
        for m in mounted {
            if Path::new(&m) != rec.root {
                self.sys.unmount(&m)?;
            }
        }
        Ok(())
    }

    pub fn jail_params(&self, rec: &Record) -> Vec<(String, String)> {
        let vnet = rec
            .annotations
            .get("org.freebsd.jail.vnet")
            .is_some_and(|v| v == "new");
        let mut p: Vec<(String, String)> = vec![
            ("name".into(), rec.jail.clone()),
            ("path".into(), rec.root.to_string_lossy().into_owned()),
            ("host.hostname".into(), rec.hostname.clone()),
            ("persist".into(), String::new()),
            ("enforce_statfs".into(), "2".into()),
            ("devfs_ruleset".into(), DEVFS_RULESET.to_string()),
        ];
        if vnet {
            p.push(("vnet".into(), String::new()));
        } else {
            p.extend([
                ("ip4".into(), "inherit".into()),
                ("ip6".into(), "inherit".into()),
            ]);
        }
        if rec.linux {
            p.push(("linux".into(), "new".into()));
        }
        for (k, v) in &rec.params {
            match p.iter_mut().find(|(n, _)| n == k) {
                Some(slot) => slot.1 = v.clone(),
                None => p.push((k.clone(), v.clone())),
            }
        }
        p
    }

    pub fn create_jail(&self, rec: &Record) -> Result<u32, Error> {
        let params = self.jail_params(rec);
        let refs: Vec<(&str, &str)> = params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.sys
            .jail_create(&refs)
            .map_err(|e| Error::Runtime(format!("creating jail {}: {e}", rec.jail)))
    }

    pub async fn create(&self, spec: &RunSpec) -> Result<Record, Error> {
        let rec = self.make_record(spec)?;
        let dir = self.container_dir(&rec.id);
        std::fs::create_dir_all(&dir)?;
        let image = self
            .images
            .find(&rec.image)?
            .ok_or_else(|| Error::NotFound(format!("{}: image not known", rec.image)))?;
        if let Err(e) = self
            .images
            .prepare_rootfs(&image, &rec.root, rec.dataset.as_deref())
        {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e.into());
        }
        state::write(&dir, RECORD, &rec)?;
        Ok(rec)
    }

    /// Runs a container according to `spec`. Returns `(container_id, exit_code)`.
    pub async fn run(&self, spec: &RunSpec) -> Result<(String, i32), Error> {
        let rec = self.create(spec).await?;
        let id = rec.id.clone();
        if spec.detach {
            if let Err(e) = self.start_detached(&rec).await {
                if spec.rm {
                    let _ = self.remove(&id).await;
                }
                return Err(e);
            }
            return Ok((id, 0));
        }

        let code = self.run_foreground(&rec, spec.interactive, spec.tty).await;
        if spec.rm {
            let _ = self.remove(&id).await;
        }
        Ok((id, code?))
    }

    async fn start_detached(&self, rec: &Record) -> Result<(), Error> {
        let dir = self.container_dir(&rec.id);
        state::remove(&dir, EXIT)?;
        state::remove(&dir, RUN)?;
        if jail_names(&*self.sys)?.contains(&rec.jail) {
            let _ = self.sys.jail_remove(&rec.jail);
        }
        self.mount(rec)?;
        let jid = match self.create_jail(rec) {
            Ok(j) => j,
            Err(e) => {
                let _ = self.unmount(rec);
                return Err(e);
            }
        };
        if let Err(e) = self.supervise(rec, jid).await {
            let _ = self.sys.jail_remove(&rec.jail);
            let _ = self.unmount(rec);
            return Err(e);
        }
        Ok(())
    }

    async fn run_foreground(
        &self,
        rec: &Record,
        interactive: bool,
        tty: bool,
    ) -> Result<i32, Error> {
        let dir = self.container_dir(&rec.id);
        state::remove(&dir, EXIT)?;
        state::remove(&dir, RUN)?;
        if jail_names(&*self.sys)?.contains(&rec.jail) {
            let _ = self.sys.jail_remove(&rec.jail);
        }
        self.mount(rec)?;
        let jid = match self.create_jail(rec) {
            Ok(j) => j,
            Err(e) => {
                let _ = self.unmount(rec);
                return Err(e);
            }
        };
        let run = Run {
            shim: std::process::id(),
            pid: std::process::id(),
            jid,
            started: state::now(),
            boot: self.boot,
        };
        let _ = state::write(&dir, RUN, &run);

        let mut args: Vec<OsString> = vec![
            "exec".into(),
            dir.clone().into_os_string(),
            jid.to_string().into(),
            if tty { "1" } else { "0" }.into(),
        ];
        args.extend(rec.argv.iter().map(OsString::from));
        let refs: Vec<&std::ffi::OsStr> = args.iter().map(OsString::as_os_str).collect();
        let mut cmd = self.shim_command(&refs);
        if interactive || tty {
            cmd.stdin(std::process::Stdio::inherit());
        } else {
            cmd.stdin(std::process::Stdio::null());
        }
        cmd.stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit());

        let status_res = cmd.status().await;
        let _ = self.sys.jail_remove(&rec.jail);
        let _ = self.unmount(rec);

        let code = match status_res {
            Ok(s) => s.code().unwrap_or(255),
            Err(e) => {
                let _ = state::write(
                    &dir,
                    EXIT,
                    &Exit {
                        code: 127,
                        finished: state::now(),
                        error: Some(e.to_string()),
                    },
                );
                return Err(Error::Runtime(format!("running {}: {e}", rec.name)));
            }
        };
        let _ = state::write(
            &dir,
            EXIT,
            &Exit {
                code,
                finished: state::now(),
                error: None,
            },
        );
        Ok(code)
    }

    async fn supervise(&self, rec: &Record, jid: u32) -> Result<(), Error> {
        use tokio::io::AsyncBufReadExt;
        let dir = self.container_dir(&rec.id);
        let shim_log = std::fs::File::create(dir.join(SHIM_LOG))?;
        let mut cmd = self.shim_command(&[
            "supervise".as_ref(),
            dir.as_os_str(),
            jid.to_string().as_ref(),
        ]);
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(shim_log);
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd
            .spawn()
            .map_err(|e| Error::Runtime(format!("starting the supervisor: {e}")))?;
        let stdout = child.stdout.take().expect("piped");
        let mut line = String::new();
        let read = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::io::BufReader::new(stdout).read_line(&mut line),
        )
        .await;
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        let line = line.trim();
        if let Some(pid) = line.strip_prefix("ok ") {
            tracing::debug!(container = %rec.name, pid, "started");
            return Ok(());
        }
        let why = match (read, line.strip_prefix("err ")) {
            (_, Some(why)) => why.to_owned(),
            (Err(_), _) => "the supervisor did not answer".to_owned(),
            _ => {
                let log = std::fs::read_to_string(dir.join(SHIM_LOG)).unwrap_or_default();
                format!("the supervisor ended: {}", log.trim())
            }
        };
        Err(Error::Runtime(format!("starting {}: {why}", rec.name)))
    }

    pub async fn exec(
        &self,
        id_or_name: &str,
        cmd_argv: &[String],
        interactive: bool,
        tty: bool,
    ) -> Result<i32, Error> {
        let rec = self.record(id_or_name)?;
        let Status::Running(run) = self.status(&rec)? else {
            return Err(Error::Runtime(format!(
                "container {} is not running",
                rec.name
            )));
        };
        let dir = self.container_dir(&rec.id);
        let mut args: Vec<OsString> = vec![
            "exec".into(),
            dir.into_os_string(),
            run.jid.to_string().into(),
            if tty { "1" } else { "0" }.into(),
        ];
        args.extend(cmd_argv.iter().map(OsString::from));
        let refs: Vec<&std::ffi::OsStr> = args.iter().map(OsString::as_os_str).collect();
        let mut command = self.shim_command(&refs);
        if interactive || tty {
            command.stdin(std::process::Stdio::inherit());
        } else {
            command.stdin(std::process::Stdio::null());
        }
        command
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit());
        let status = command.status().await?;
        Ok(status.code().unwrap_or(255))
    }

    pub async fn stop(&self, id_or_name: &str, timeout: Option<Duration>) -> Result<(), Error> {
        let rec = self.record(id_or_name)?;
        let Status::Running(_run) = self.status(&rec)? else {
            return Ok(());
        };
        let wait_dur = timeout.unwrap_or_else(|| Duration::from_secs(rec.stop_timeout));
        #[cfg(unix)]
        if alive(_run.shim) {
            unsafe { libc::kill(_run.shim as libc::pid_t, libc::SIGTERM) };
        }
        if self.wait_over(&rec, wait_dur).await? {
            let _ = self.unmount(&rec);
            return Ok(());
        }
        match self.sys.jail_remove(&rec.jail) {
            Ok(()) | Err(crate::sys::Error::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
        let _ = self.unmount(&rec);
        if !self.wait_over(&rec, Duration::from_secs(5)).await? {
            state::write(
                &self.container_dir(&rec.id),
                EXIT,
                &Exit {
                    code: 137,
                    finished: state::now(),
                    error: None,
                },
            )?;
        }
        Ok(())
    }

    pub async fn remove(&self, id_or_name: &str) -> Result<(), Error> {
        let rec = self.record(id_or_name)?;
        self.stop(&rec.id, Some(Duration::ZERO)).await?;
        let _ = self.unmount(&rec);
        self.images
            .cleanup_rootfs(&rec.root, rec.dataset.as_deref())?;
        let cdir = self.container_dir(&rec.id);
        if cdir.exists() {
            std::fs::remove_dir_all(cdir)?;
        }
        Ok(())
    }

    pub fn list(&self, all: bool) -> Result<Vec<ContainerSummary>, Error> {
        let jails = jail_names(&*self.sys)?;
        let mut out = Vec::new();
        for rec in records(&self.dir)? {
            let s = status(&self.dir, &rec, self.boot, &jails)?;
            if !all && !matches!(s, Status::Running(_)) {
                continue;
            }
            out.push(ContainerSummary {
                id: rec.id,
                name: rec.name,
                image: rec.image,
                status: s,
                created: rec.created,
            });
        }
        Ok(out)
    }

    pub fn logs(&self, id_or_name: &str, tail: Option<usize>) -> Result<Vec<log::Chunk>, Error> {
        let rec = self.record(id_or_name)?;
        let path = self.container_dir(&rec.id).join(LOG);
        Ok(log::read_all(&path, tail)?)
    }

    async fn wait_over(&self, rec: &Record, within: Duration) -> Result<bool, Error> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if !matches!(self.status(rec)?, Status::Running(_)) {
                return Ok(true);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Executes a `RUN` build instruction inside a temporary FreeBSD jail
    /// rooted at `root`, using the same `jail-shim` user/env/workdir logic as
    /// `jailer run`.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_build_step(
        &self,
        root: &Path,
        argv: &[String],
        env: &[String],
        user: &str,
        work_dir: &str,
        mounts: &[BuildMount],
        no_network: bool,
    ) -> Result<(), Error> {
        let id = new_id();
        let step_dir = self.dir.join(format!("build-{id}"));
        std::fs::create_dir_all(&step_dir)?;
        let jail_name = format!("jailer_build_{}", &id[..12]);

        // Ensure work_dir exists in root
        let _ = target(root, work_dir, false)?;

        // Temporarily provide /etc/resolv.conf if absent or empty so `pkg`
        // can resolve mirrors during `RUN` steps.
        let resolv_target = target(root, "/etc/resolv.conf", true)?;
        let had_resolv = std::fs::metadata(&resolv_target).is_ok_and(|m| m.len() > 0);
        if !had_resolv && Path::new("/etc/resolv.conf").exists() {
            let _ = std::fs::copy("/etc/resolv.conf", &resolv_target);
        }

        let rec = Record {
            id: id.clone(),
            name: jail_name.clone(),
            image: "build".to_owned(),
            created: state::now(),
            labels: BTreeMap::new(),
            annotations: if no_network {
                BTreeMap::from([("org.freebsd.jail.vnet".to_owned(), "new".to_owned())])
            } else {
                BTreeMap::new()
            },
            parent: None,
            jail: jail_name.clone(),
            root: root.to_path_buf(),
            dataset: None,
            argv: argv.to_vec(),
            env: env.to_vec(),
            user: user.to_owned(),
            work_dir: if work_dir.is_empty() {
                "/".to_owned()
            } else {
                work_dir.to_owned()
            },
            hostname: "build".to_owned(),
            mounts: Vec::new(),
            params: vec![("allow.chflags".to_owned(), "true".to_owned())],
            stop_signal: 15,
            stop_timeout: 10,
            linux: false,
        };
        state::write(&step_dir, RECORD, &rec)?;

        let dev = target(root, "/dev", false)?;
        self.sys
            .mount_devfs(&dev.to_string_lossy(), DEVFS_RULESET)?;

        let mut mounted = Vec::new();
        let jid_res = self
            .mount_build(root, mounts, &mut mounted)
            .and_then(|()| self.create_jail(&rec));
        let jid = match jid_res {
            Ok(j) => j,
            Err(e) => {
                self.release_build_mounts(&mounted);
                let _ = self.sys.unmount(&dev.to_string_lossy());
                if !had_resolv {
                    let _ = std::fs::remove_file(&resolv_target);
                }
                let _ = std::fs::remove_dir_all(&step_dir);
                return Err(e);
            }
        };

        let mut args: Vec<OsString> = vec![
            "exec".into(),
            step_dir.clone().into_os_string(),
            jid.to_string().into(),
            "0".into(),
        ];
        args.extend(argv.iter().map(OsString::from));
        let refs: Vec<&std::ffi::OsStr> = args.iter().map(OsString::as_os_str).collect();
        let mut cmd = self.shim_command(&refs);
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit());
        let status_res = cmd.status().await;

        let _ = self.sys.jail_remove(&jail_name);
        self.release_build_mounts(&mounted);
        let _ = self.sys.unmount(&dev.to_string_lossy());
        if !had_resolv {
            let _ = std::fs::remove_file(&resolv_target);
        }
        let _ = std::fs::remove_dir_all(&step_dir);

        let status = status_res?;
        if !status.success() {
            return Err(Error::Build(format!(
                "RUN command {:?} exited with status {}",
                argv.join(" "),
                status.code().unwrap_or(1)
            )));
        }
        Ok(())
    }
}

impl JailRuntime {
    /// Mounts a build step's mounts under `root`, recording each mount point
    /// and the first directory or file made for it, to undo afterwards.
    fn mount_build(
        &self,
        root: &Path,
        mounts: &[BuildMount],
        mounted: &mut Vec<(PathBuf, Option<PathBuf>)>,
    ) -> Result<(), Error> {
        for m in mounts {
            let (dest, file) = match m {
                BuildMount::Nullfs { source, target, .. } => (target, source.is_file()),
                BuildMount::Tmpfs { target, .. } => (target, false),
            };
            let made = first_missing(root, dest);
            let at = target(root, dest, file)?;
            mounted.push((at.clone(), made));
            let at = at.to_string_lossy();
            match m {
                BuildMount::Nullfs {
                    source, read_only, ..
                } => self
                    .sys
                    .mount_nullfs(&source.to_string_lossy(), &at, *read_only)?,
                BuildMount::Tmpfs { size, .. } => self.sys.mount_tmpfs(&at, *size, 0o1777)?,
            }
        }
        Ok(())
    }

    /// Unmounts a build step's mounts, last first, and removes the mount
    /// points made for them that the step left empty.
    fn release_build_mounts(&self, mounted: &[(PathBuf, Option<PathBuf>)]) {
        for (at, made) in mounted.iter().rev() {
            let _ = self.sys.unmount(&at.to_string_lossy());
            let Some(made) = made else { continue };
            let mut cur = at.clone();
            loop {
                let removed = match std::fs::symlink_metadata(&cur) {
                    Ok(m) if m.is_dir() => std::fs::remove_dir(&cur).is_ok(),
                    Ok(m) if m.is_file() && m.len() == 0 => std::fs::remove_file(&cur).is_ok(),
                    _ => false,
                };
                if !removed || cur == *made {
                    break;
                }
                match cur.parent() {
                    Some(p) => cur = p.to_path_buf(),
                    None => break,
                }
            }
        }
    }
}

/// The first missing path on the way from `root` to `dest` inside it.
fn first_missing(root: &Path, dest: &str) -> Option<PathBuf> {
    let mut path = root.to_path_buf();
    for c in Path::new(dest).components() {
        if let Component::Normal(name) = c {
            path.push(name);
            if std::fs::symlink_metadata(&path).is_err() {
                return Some(path);
            }
        }
    }
    None
}

/// A mount for one `RUN` step.
#[derive(Debug, Clone)]
pub enum BuildMount {
    /// A host file or directory, mounted with nullfs at `target`.
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

fn records(dir: &Path) -> Result<Vec<Record>, Error> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        if e.path().is_dir()
            && let Some(r) = state::read::<Record>(&e.path(), RECORD)?
        {
            out.push(r);
        }
    }
    out.sort_by_key(|r| r.created);
    Ok(out)
}

fn jail_names(sys: &dyn Sys) -> Result<BTreeSet<String>, Error> {
    Ok(sys.jails()?.into_iter().map(|j| j.name).collect())
}

fn status(dir: &Path, rec: &Record, boot: u64, jails: &BTreeSet<String>) -> Result<Status, Error> {
    let cdir = dir.join(&rec.id);
    if let Some(exit) = state::read::<Exit>(&cdir, EXIT)? {
        return Ok(Status::Exited(exit));
    }
    let Some(run) = state::read::<Run>(&cdir, RUN)? else {
        return Ok(Status::Created);
    };
    let here = jails.contains(&rec.jail);
    let running = run.boot == boot && (here || alive(run.shim));
    if running {
        return Ok(Status::Running(run));
    }
    Ok(Status::Exited(Exit {
        code: 255,
        finished: run.started,
        error: None,
    }))
}
