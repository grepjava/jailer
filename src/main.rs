use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use jailer::auth::{resolve_credentials, save_credentials};
use jailer::build::{BuildBackend, BuildOptions};
use jailer::check::{CheckReport, Severity, check_containerfile, check_image};
use jailer::containerfile::Containerfile;
use jailer::init::{InitOptions, Template, detect_app_name};
use jailer::registry::Client;
use jailer::runtime::{Config, JailRuntime};
use jailer::store::Store;
use jailer::sys::{Shell, Sys};
use jailer::{Reference, shim};

#[derive(Parser, Debug)]
#[command(
    name = "jailer",
    version,
    about = "Build, test, and publish FreeBSD jail OCI images for Legion"
)]
pub struct Cli {
    /// Directory where jailer keeps images and container state
    #[arg(long, env = "JAILER_STATE_DIR", global = true, value_name = "DIR")]
    pub state_dir: Option<PathBuf>,

    /// ZFS root dataset for image layers and container clones (e.g. zroot/jailer)
    #[arg(long, env = "JAILER_ZFS_ROOT", global = true, value_name = "DATASET")]
    pub zfs_root: Option<String>,

    /// Use plain directory storage instead of ZFS
    #[arg(long, env = "JAILER_NO_ZFS", global = true)]
    pub no_zfs: bool,

    /// Talk to this registry over plain HTTP instead of HTTPS
    #[arg(long, global = true, value_name = "HOST[:PORT]")]
    pub plain_http: Vec<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scaffold a FreeBSD Containerfile and .containerignore
    Init {
        /// Project template (auto-detected from Cargo.toml, go.mod, etc. if omitted)
        #[arg(long, short = 'T', value_enum)]
        template: Option<Template>,

        /// FreeBSD base image release tag [default: host release or 15.1]
        #[arg(long, short = 'r')]
        release: Option<String>,

        /// Application or binary name [default: inferred from project]
        #[arg(long, short = 'n')]
        name: Option<String>,

        /// Overwrite existing Containerfile
        #[arg(long, short = 'f')]
        force: bool,

        /// Project directory [default: .]
        #[arg(default_value = ".")]
        dir: PathBuf,
    },

    /// Build a FreeBSD OCI image from a Containerfile
    Build {
        /// Name and optional tag for the image [default: localhost/<dir>:latest]
        #[arg(short = 't', long = "tag", value_name = "NAME[:TAG]")]
        tag: Option<String>,

        /// Path to the Containerfile [default: <context>/Containerfile]
        #[arg(short = 'f', long = "file", value_name = "PATH")]
        file: Option<PathBuf>,

        /// Build-time variable (KEY=VALUE)
        #[arg(long = "build-arg", value_name = "KEY=VALUE")]
        build_args: Vec<String>,

        /// Target build stage to stop at
        #[arg(long, value_name = "STAGE")]
        target: Option<String>,

        /// Build backend (`native` or `buildah`)
        #[arg(long, value_enum, default_value_t = BuildBackend::Native)]
        backend: BuildBackend,

        /// Fail the build if Legion compatibility checks report an error
        #[arg(long)]
        strict: bool,

        /// Run every RUN step instead of reusing cached results
        #[arg(long)]
        no_cache: bool,

        /// Flatten the image, base included, into one layer
        #[arg(long)]
        squash: bool,

        /// Keep cached layers that no image uses to about this size (e.g. 10g, or `none`)
        #[arg(
            long,
            env = "JAILER_CACHE_MAX",
            default_value = "10g",
            value_name = "SIZE"
        )]
        cache_max: String,

        /// A secret for `RUN --mount=type=secret`: id=ID,src=FILE or id=ID,env=VAR
        #[arg(long = "secret", value_name = "id=ID,src=FILE")]
        secrets: Vec<String>,

        /// An SSH agent for `RUN --mount=type=ssh`: ID (from $SSH_AUTH_SOCK) or ID=SOCKET
        #[arg(long = "ssh", value_name = "ID[=SOCKET]")]
        ssh: Vec<String>,

        /// A jail(8) parameter for `RUN` steps (KEY=VALUE)
        #[arg(long = "param", value_name = "KEY=VALUE")]
        params: Vec<String>,

        /// Give `RUN` steps SysV IPC of their own (`msg`, `sem`, `shm`)
        #[arg(long, value_delimiter = ',')]
        sysv: Vec<String>,

        #[command(flatten)]
        limits: LimitArgs,

        /// A label for the image (KEY=VALUE), over the Containerfile's
        #[arg(long = "label", value_name = "KEY=VALUE")]
        labels: Vec<String>,

        /// The image's creation time, in seconds since 1970 [default: none,
        /// so that a build is reproducible]
        #[arg(long, env = "SOURCE_DATE_EPOCH", value_name = "SECONDS")]
        timestamp: Option<i64>,

        /// Registry credentials for pulling base images (USER[:PASSWORD])
        #[arg(long, value_name = "USER[:PASSWORD]")]
        creds: Option<String>,

        /// Path to Docker/Podman auth.json file
        #[arg(long, value_name = "PATH")]
        authfile: Option<PathBuf>,

        /// Build context directory [default: .]
        #[arg(default_value = ".")]
        context: PathBuf,
    },

    /// Run and test an image locally in a FreeBSD jail matching Legion's runtime
    Run {
        /// Remove the container and its rootfs when it exits
        #[arg(long)]
        rm: bool,

        /// Run the container in the background and print its ID
        #[arg(short = 'd', long)]
        detach: bool,

        /// Keep STDIN open
        #[arg(short = 'i', long)]
        interactive: bool,

        /// Allocate a pseudo-TTY
        #[arg(short = 't', long)]
        tty: bool,

        /// Assign a name to the container
        #[arg(long, value_name = "NAME")]
        name: Option<String>,

        /// Set environment variables (KEY=VALUE)
        #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Mount a host path into the container via nullfs (SRC:DEST[:ro])
        #[arg(short = 'v', long = "volume", value_name = "SRC:DEST[:ro]")]
        volumes: Vec<String>,

        /// Username or UID (format: <name|uid>[:<group|gid>])
        #[arg(short = 'u', long, value_name = "USER[:GROUP]")]
        user: Option<String>,

        /// Working directory inside the container
        #[arg(short = 'w', long = "workdir", value_name = "DIR")]
        workdir: Option<String>,

        /// Container hostname
        #[arg(long, value_name = "HOSTNAME")]
        hostname: Option<String>,

        /// Override the image's default ENTRYPOINT
        #[arg(long, value_name = "BIN")]
        entrypoint: Option<String>,

        /// Run in a pod with a network stack of its own, on jailer's bridge
        /// (`--network bridge`)
        #[arg(long)]
        vnet: bool,

        /// The network: the host's, jailer's bridge (as `--vnet`), or none
        /// (a pod with only its loopback)
        #[arg(long, value_enum, default_value_t = NetworkArg::Host)]
        network: NetworkArg,

        /// Publish a port on the host: [IP:]HOST:CONTAINER[/tcp|udp]
        /// (implies `--vnet`)
        #[arg(short = 'p', long = "publish", value_name = "[IP:]HOST:CONTAINER")]
        publish: Vec<String>,

        /// Allow mlock(2) inside the jail (`org.freebsd.jail.allow.mlock=true`)
        #[arg(long)]
        allow_mlock: bool,

        /// Enable SysV IPC namespaces (`msg`, `sem`, `shm`)
        #[arg(long, value_delimiter = ',')]
        sysv: Vec<String>,

        /// Additional raw jail(8) parameters (KEY=VALUE)
        #[arg(long = "param", value_name = "KEY=VALUE")]
        params: Vec<String>,

        #[command(flatten)]
        limits: LimitArgs,

        /// Run a Linux image through FreeBSD's Linux ABI (`linux(4)`)
        #[arg(long)]
        linux: bool,

        /// Image to run [default: current directory's built image] and optional command
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Publish an image to an OCI registry for Legion
    Push {
        /// Registry credentials (USER[:PASSWORD])
        #[arg(long, value_name = "USER[:PASSWORD]")]
        creds: Option<String>,

        /// Path to Docker/Podman auth.json file
        #[arg(long, value_name = "PATH")]
        authfile: Option<PathBuf>,

        /// `<target-reference>` (pushes current project's image) or `<source-image> <target-reference>`
        #[arg(required = true, num_args = 1..=2)]
        refs: Vec<String>,
    },

    /// Publish or inspect multi-architecture image indexes
    #[command(subcommand)]
    Manifest(ManifestCommand),

    /// Produce an offline OCI archive (`app.tar`) for `legion image load`
    Export {
        /// Output tar archive path
        #[arg(short = 'o', long = "output", value_name = "PATH")]
        output: Option<PathBuf>,

        /// Override image reference recorded in the archive's `index.json`
        #[arg(long, value_name = "REF")]
        name: Option<String>,

        /// `<output.tar>` (exports current project's image) or `<image> [output.tar]`
        #[arg(num_args = 1..=2)]
        args: Vec<String>,
    },

    /// Check a Containerfile or built image for Legion compatibility
    Check {
        /// Image reference or directory containing a Containerfile [default: .]
        #[arg(default_value = ".")]
        target: String,
    },

    /// Pull an image from an OCI registry into the local store
    Pull {
        /// Registry credentials (USER[:PASSWORD])
        #[arg(long, value_name = "USER[:PASSWORD]")]
        creds: Option<String>,

        /// Path to Docker/Podman auth.json file
        #[arg(long, value_name = "PATH")]
        authfile: Option<PathBuf>,

        /// Allow Linux images when no FreeBSD image is offered
        #[arg(long)]
        linux: bool,

        /// Image reference to pull
        reference: String,
    },

    /// Load an image from an OCI archive (`app.tar`) into the local store
    Load {
        /// Override the image name
        #[arg(long, value_name = "REF")]
        name: Option<String>,

        /// Path to the OCI archive tar
        archive: PathBuf,
    },

    /// Save registry login credentials to ~/.docker/config.json
    Login {
        /// Username
        #[arg(short = 'u', long)]
        username: String,

        /// Password or token
        #[arg(short = 'p', long)]
        password: String,

        /// Path to auth file
        #[arg(long, value_name = "PATH")]
        authfile: Option<PathBuf>,

        /// Registry host (e.g. ghcr.io, docker.io)
        registry: String,
    },

    /// List images in the local store
    Images,

    /// Remove an image from the local store
    Rmi {
        /// Image reference or ID
        reference: String,
    },

    /// Remove layers and blobs no image or build cache entry uses
    Prune {
        /// Also clear the build cache
        #[arg(long)]
        cache: bool,
    },

    /// List local containers
    Ps {
        /// Show all containers (default shows just running)
        #[arg(short = 'a', long)]
        all: bool,
    },

    /// Fetch the logs of a container
    Logs {
        /// Number of lines to show from the end of the logs
        #[arg(long, short = 'n')]
        tail: Option<usize>,

        /// Container ID or name
        container: String,
    },

    /// Execute a command in a running container
    Exec {
        /// Keep STDIN open
        #[arg(short = 'i', long)]
        interactive: bool,

        /// Allocate a pseudo-TTY
        #[arg(short = 't', long)]
        tty: bool,

        /// Container ID or name
        container: String,

        /// Command and arguments
        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Stop a running container
    Stop {
        /// Seconds to wait before killing the jail
        #[arg(short = 't', long)]
        time: Option<u64>,

        /// Container ID or name
        container: String,
    },

    /// Remove one or more containers
    Rm {
        /// Stop running containers before removing them
        #[arg(short, long)]
        force: bool,

        /// Container IDs or names
        #[arg(required = true)]
        containers: Vec<String>,
    },

    /// Internal supervisor shim for jails
    #[command(name = "jail-shim", hide = true)]
    JailShim {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

/// Reads `--secret id=ID,src=FILE` and `--secret id=ID,env=VAR` values.
fn parse_secrets(specs: &[String]) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut out = BTreeMap::new();
    for spec in specs {
        let kv: BTreeMap<&str, &str> = spec.split(',').filter_map(|p| p.split_once('=')).collect();
        let id = kv
            .get("id")
            .with_context(|| format!("--secret {spec:?}: give id=ID"))?;
        let value = match (kv.get("src").or(kv.get("source")), kv.get("env")) {
            (Some(path), None) => {
                std::fs::read(path).with_context(|| format!("--secret {id}: reading {path}"))?
            }
            (None, Some(var)) => std::env::var(var)
                .with_context(|| format!("--secret {id}: ${var} is not set"))?
                .into_bytes(),
            _ => bail!("--secret {spec:?}: give one of src=FILE or env=VAR"),
        };
        if out.insert((*id).to_owned(), value).is_some() {
            bail!("--secret {id} given twice");
        }
    }
    Ok(out)
}

/// Reads `--ssh ID` (the agent at $SSH_AUTH_SOCK) and `--ssh ID=SOCKET`.
fn parse_ssh(specs: &[String]) -> Result<BTreeMap<String, PathBuf>> {
    let mut out = BTreeMap::new();
    for spec in specs {
        let (id, path) = match spec.split_once('=') {
            Some((id, path)) => (id, PathBuf::from(path)),
            None => (
                spec.as_str(),
                std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from).with_context(|| {
                    format!(
                        "--ssh {spec}: $SSH_AUTH_SOCK is not set (sudo drops it: give --ssh {spec}=\"$SSH_AUTH_SOCK\")"
                    )
                })?,
            ),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            let meta = std::fs::metadata(&path)
                .with_context(|| format!("--ssh {id}: {}", path.display()))?;
            if !meta.file_type().is_socket() {
                bail!(
                    "--ssh {id}: {} is not an agent socket (key files are not supported)",
                    path.display()
                );
            }
        }
        if out.insert(id.to_owned(), path).is_some() {
            bail!("--ssh {id} given twice");
        }
    }
    Ok(out)
}

/// Jails can only be created or entered by root; fail before pulling anything.
#[cfg(unix)]
fn require_root(what: &str) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("`jailer {what}` needs root to create jails; run it with sudo or doas");
    }
    Ok(())
}

#[derive(Subcommand, Debug)]
pub enum ManifestCommand {
    /// Push an index naming one image per platform, e.g. an amd64 and an
    /// arm64 build of the same app
    Push {
        /// Registry credentials (USER[:PASSWORD])
        #[arg(long, value_name = "USER[:PASSWORD]")]
        creds: Option<String>,

        /// Path to Docker/Podman auth.json file
        #[arg(long, value_name = "PATH")]
        authfile: Option<PathBuf>,

        /// Registry reference to push the index to (e.g. ghcr.io/me/app:1.0)
        target: String,

        /// Local images, or images already pushed to the target's repository
        #[arg(required = true)]
        sources: Vec<String>,
    },

    /// Print the manifest or index a registry holds for a reference
    Inspect {
        /// Registry credentials (USER[:PASSWORD])
        #[arg(long, value_name = "USER[:PASSWORD]")]
        creds: Option<String>,

        /// Path to Docker/Podman auth.json file
        #[arg(long, value_name = "PATH")]
        authfile: Option<PathBuf>,

        /// Image reference
        reference: String,
    },
}

fn default_state_dir() -> PathBuf {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        return PathBuf::from("/var/db/jailer");
    }
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("jailer");
    }
    PathBuf::from("/var/db/jailer")
}

fn resolve_zfs_root(cli: &Cli, sys: &dyn Sys) -> Option<String> {
    if cli.no_zfs {
        return None;
    }
    if let Some(ds) = &cli.zfs_root {
        return Some(ds.clone());
    }
    #[cfg(target_os = "freebsd")]
    if unsafe { libc::geteuid() } == 0 && jailer::sys::zfs_available() {
        // Auto-detect the top-level pool (typically `zroot`)
        if let Ok(list) = sys.zfs_list("zroot")
            && !list.is_empty()
        {
            return Some("zroot/jailer".to_owned());
        }
    }
    let _ = sys;
    None
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkArg {
    Host,
    Bridge,
    None,
}

/// Resource limits, held by rctl(8).
#[derive(clap::Args, Debug, Clone)]
pub struct LimitArgs {
    /// Memory limit for each process (e.g. 512m); one going past it is killed
    #[arg(short = 'm', long, value_name = "SIZE")]
    memory: Option<String>,

    /// CPU time limit, in CPUs (e.g. 1.5)
    #[arg(long, value_name = "N")]
    cpus: Option<String>,

    /// Limit on processes at a time
    #[arg(long = "pids-limit", value_name = "N")]
    pids_limit: Option<u64>,
}

impl LimitArgs {
    fn parse(&self) -> Result<jailer::runtime::Limits> {
        Ok(jailer::runtime::Limits::parse(
            self.memory.as_deref(),
            self.cpus.as_deref(),
            self.pids_limit,
        )?)
    }
}

fn open_context(cli: &Cli, linux: bool) -> Result<(Arc<dyn Sys>, Arc<Store>, JailRuntime)> {
    let sys: Arc<dyn Sys> = Arc::new(Shell::new());
    let state_dir = cli.state_dir.clone().unwrap_or_else(default_state_dir);
    let zfs_root = resolve_zfs_root(cli, &*sys);
    let images_zfs = zfs_root.as_ref().map(|r| format!("{r}/images"));
    let jails_zfs = zfs_root.as_ref().map(|r| format!("{r}/jails"));

    let mut client = Client::new()?;
    for host in &cli.plain_http {
        client = client.plain_http(host);
    }

    let images_dir = state_dir.join("images");
    let store = Arc::new(
        jailer::store::open(sys.clone(), images_zfs.as_deref(), &images_dir, client)?
            .with_linux(linux),
    );
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("jailer"));
    let runtime = JailRuntime::new(
        sys.clone(),
        store.clone(),
        Config {
            state_dir: state_dir.join("containers"),
            dataset: jails_zfs,
            shim: vec![exe.into_os_string(), OsString::from("jail-shim")],
            // The store is the builds' too, and its cache's.
            prune_images: false,
        },
    )?;
    Ok((sys, store, runtime))
}

fn print_report(report: &CheckReport) {
    for f in &report.findings {
        let prefix = match f.severity {
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        eprintln!("{prefix}[{}]: {}", f.code, f.message);
    }
}

fn default_local_image_for_cwd() -> String {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let name = detect_app_name(&cwd).to_ascii_lowercase();
    format!("localhost/{name}:latest")
}

#[tokio::main]
async fn main() -> Result<()> {
    // Handle `jail-shim` immediately before initializing async logging if invoked directly.
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.get(1).map(String::as_str) == Some("jail-shim") {
        std::process::exit(shim::main(&raw_args[2..]));
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::JailShim { args } => {
            std::process::exit(shim::main(args));
        }

        Commands::Init {
            template,
            release,
            name,
            force,
            dir,
        } => {
            let outcome = jailer::init::scaffold(&InitOptions {
                dir: dir.clone(),
                template: *template,
                release: release.clone(),
                name: name.clone(),
                force: *force,
            })?;
            println!(
                "Scaffolded {} (template: {}, FreeBSD {}, app: {})",
                outcome.containerfile.display(),
                outcome.template.as_str(),
                outcome.release,
                outcome.app_name
            );
            if let Some(ig) = outcome.containerignore {
                println!("Created {}", ig.display());
            }
            Ok(())
        }

        Commands::Build {
            tag,
            file,
            build_args,
            target,
            backend,
            strict,
            no_cache,
            squash,
            cache_max,
            secrets,
            ssh,
            params,
            sysv,
            limits,
            labels,
            timestamp,
            creds,
            authfile,
            context,
        } => {
            let (_, store, runtime) = open_context(&cli, false)?;
            let tag = match tag {
                Some(t) => t.clone(),
                None => {
                    let app = detect_app_name(context).to_ascii_lowercase();
                    format!("localhost/{app}:latest")
                }
            };
            let mut parsed_args = BTreeMap::new();
            for kv in build_args {
                let (k, v) = kv
                    .split_once('=')
                    .with_context(|| format!("--build-arg {kv:?} must be KEY=VALUE"))?;
                parsed_args.insert(k.to_owned(), v.to_owned());
            }
            let mut parsed_labels = BTreeMap::new();
            for kv in labels {
                let (k, v) = kv
                    .split_once('=')
                    .with_context(|| format!("--label {kv:?} must be KEY=VALUE"))?;
                parsed_labels.insert(k.to_owned(), v.to_owned());
            }
            let resolved_creds =
                resolve_credentials("docker.io", creds.as_deref(), authfile.as_deref())?;
            let res = jailer::build::build(
                &store,
                &runtime,
                &BuildOptions {
                    context_dir: context.clone(),
                    containerfile: file.clone(),
                    tag,
                    build_args: parsed_args,
                    target: target.clone(),
                    backend: *backend,
                    creds: resolved_creds,
                    strict_lint: *strict,
                    no_cache: *no_cache,
                    squash: *squash,
                    cache_max: match cache_max.as_str() {
                        "none" => None,
                        v => Some(jailer::containerfile::parse_size(v).ok_or_else(|| {
                            anyhow::anyhow!("--cache-max {v:?}: give a size such as 10g, or none")
                        })?),
                    },
                    secrets: parse_secrets(secrets)?,
                    ssh: parse_ssh(ssh)?,
                    jail_params: jailer::runtime::step_params(params, sysv)?,
                    labels: parsed_labels,
                    timestamp: *timestamp,
                    limits: limits.parse()?,
                },
            )
            .await?;

            print_report(&res.report);
            let name = res
                .image
                .references
                .first()
                .map(String::as_str)
                .unwrap_or("");
            println!("Built {} ({})", name, res.image.id);
            Ok(())
        }

        Commands::Push {
            creds,
            authfile,
            refs,
        } => {
            let (_, store, _) = open_context(&cli, true)?;
            let (source_image, target_str) = match refs.as_slice() {
                [only] => {
                    // If `only` already names an image in the store, push it directly;
                    // otherwise push the current directory's built image to `only`.
                    if store.find(only)?.is_some() {
                        (only.clone(), only.clone())
                    } else {
                        (default_local_image_for_cwd(), only.clone())
                    }
                }
                [src, dst] => (src.clone(), dst.clone()),
                _ => unreachable!(),
            };
            let target_ref = Reference::parse(&target_str)?;
            let resolved_creds =
                resolve_credentials(&target_ref.registry, creds.as_deref(), authfile.as_deref())?;
            let digest = store
                .push(&source_image, &target_ref, resolved_creds.as_ref())
                .await?;
            println!("Pushed {} ({digest})", target_ref);
            Ok(())
        }

        Commands::Manifest(ManifestCommand::Push {
            creds,
            authfile,
            target,
            sources,
        }) => {
            let (_, store, _) = open_context(&cli, true)?;
            let target_ref = Reference::parse(target)?;
            let resolved_creds =
                resolve_credentials(&target_ref.registry, creds.as_deref(), authfile.as_deref())?;
            let digest = store
                .push_index(&target_ref, sources, resolved_creds.as_ref())
                .await?;
            println!("Pushed {target_ref} ({digest})");
            Ok(())
        }

        Commands::Manifest(ManifestCommand::Inspect {
            creds,
            authfile,
            reference,
        }) => {
            let (_, store, _) = open_context(&cli, true)?;
            let r = Reference::parse(reference)?;
            let resolved_creds =
                resolve_credentials(&r.registry, creds.as_deref(), authfile.as_deref())?;
            let (digest, doc) = store
                .client()
                .document(&r, r.target(), resolved_creds.as_ref())
                .await?;
            println!("{}", serde_json::to_string_pretty(&doc)?);
            eprintln!("{digest}");
            Ok(())
        }

        Commands::Export { output, name, args } => {
            let (_, store, _) = open_context(&cli, true)?;
            let (image_ref, out_path) = match (output, args.as_slice()) {
                (Some(out), [img]) => (img.clone(), out.clone()),
                (Some(out), []) => (default_local_image_for_cwd(), out.clone()),
                (None, [single]) => {
                    if single.ends_with(".tar") || single.contains(['/', '\\']) {
                        (default_local_image_for_cwd(), PathBuf::from(single))
                    } else {
                        (single.clone(), PathBuf::from("app.tar"))
                    }
                }
                (None, [img, out]) => (img.clone(), PathBuf::from(out)),
                _ => bail!("usage: jailer export [IMAGE] <OUTPUT.tar>"),
            };
            let img = store.export(&image_ref, &out_path, name.as_deref()).await?;
            let shown = name
                .as_deref()
                .or_else(|| img.references.first().map(String::as_str))
                .unwrap_or(&image_ref);
            println!("Exported {} to {}", shown, out_path.display());
            Ok(())
        }

        Commands::Check { target } => {
            let mut report = CheckReport::default();
            let path = Path::new(target);
            let cf_candidate = if path.is_dir() {
                let c1 = path.join("Containerfile");
                let c2 = path.join("Dockerfile");
                if c1.exists() {
                    Some(c1)
                } else if c2.exists() {
                    Some(c2)
                } else {
                    None
                }
            } else if path.is_file() {
                Some(path.to_path_buf())
            } else {
                None
            };

            let mut checked_something = false;
            if let Some(cf_path) = cf_candidate {
                let cf = Containerfile::parse_file(&cf_path)?;
                report.merge(check_containerfile(&cf));
                checked_something = true;
            }

            let (_, store, _) = open_context(&cli, true)?;
            let img_lookup = if target == "." {
                default_local_image_for_cwd()
            } else {
                target.clone()
            };
            if let Some(img) = store.find(&img_lookup)? {
                let tmp = tempfile::Builder::new()
                    .prefix("check")
                    .tempdir_in(store.dir().join("tmp"))?;
                if store.prepare_rootfs(&img, tmp.path(), None).is_ok() {
                    report.merge(check_image(&img.config, Some(tmp.path())));
                    let _ = store.cleanup_rootfs(tmp.path(), None);
                } else {
                    report.merge(check_image(&img.config, None));
                }
                checked_something = true;
            }

            if !checked_something {
                bail!("no Containerfile or local image found for {target:?}");
            }

            print_report(&report);
            if report.has_errors() {
                bail!("Legion compatibility check failed");
            }
            println!(
                "Legion compatibility check passed ({} warning(s))",
                report.findings.len()
            );
            Ok(())
        }

        Commands::Pull {
            creds,
            authfile,
            linux,
            reference,
        } => {
            let (_, store, _) = open_context(&cli, *linux)?;
            let r = Reference::parse(reference)?;
            let resolved_creds =
                resolve_credentials(&r.registry, creds.as_deref(), authfile.as_deref())?;
            let img = store
                .pull(reference, resolved_creds.as_ref(), "root")
                .await?;
            println!("Pulled {} ({})", r, img.id);
            Ok(())
        }

        Commands::Load { name, archive } => {
            let (_, store, _) = open_context(&cli, true)?;
            let img = store.load(archive, name.as_deref()).await?;
            println!(
                "Loaded {} ({})",
                img.references.first().map(String::as_str).unwrap_or(""),
                img.id
            );
            Ok(())
        }

        Commands::Login {
            username,
            password,
            authfile,
            registry,
        } => {
            let path = save_credentials(
                registry,
                &jailer::Credentials {
                    username: username.clone(),
                    password: password.clone(),
                },
                authfile.as_deref(),
            )?;
            println!(
                "Login succeeded for {registry} (saved to {})",
                path.display()
            );
            Ok(())
        }

        Commands::Images => {
            let (_, store, _) = open_context(&cli, true)?;
            let images = store.images()?;
            let w = images
                .iter()
                .flat_map(|i| i.references.iter().map(String::len))
                .chain(["REFERENCE".len()])
                .max()
                .unwrap_or(0);
            println!(
                "{:<w$}  {:<16} {:<16} LAYERS",
                "REFERENCE", "IMAGE ID", "PLATFORM"
            );
            for img in images {
                let short_id = img
                    .id
                    .strip_prefix("sha256:")
                    .unwrap_or(&img.id)
                    .chars()
                    .take(12)
                    .collect::<String>();
                let plat = format!(
                    "{}/{}",
                    if img.config.os.is_empty() {
                        "freebsd"
                    } else {
                        &img.config.os
                    },
                    if img.config.architecture.is_empty() {
                        jailer::oci::arch()
                    } else {
                        &img.config.architecture
                    }
                );
                for r in &img.references {
                    println!(
                        "{:<w$}  {:<16} {:<16} {}",
                        r,
                        short_id,
                        plat,
                        img.layers.len()
                    );
                }
            }
            Ok(())
        }

        Commands::Prune { cache } => {
            let (_, store, _) = open_context(&cli, true)?;
            let n = jailer::store::prune(&store, *cache).await?;
            println!("Removed {n} layer(s)");
            Ok(())
        }

        Commands::Rmi { reference } => {
            let (_, store, _) = open_context(&cli, true)?;
            if jailer::store::remove(&store, reference).await? {
                println!("Removed {reference}");
            } else {
                bail!("image {reference:?} not found");
            }
            Ok(())
        }

        Commands::Run { .. }
        | Commands::Ps { .. }
        | Commands::Logs { .. }
        | Commands::Exec { .. }
        | Commands::Stop { .. }
        | Commands::Rm { .. } => containers(&cli).await,
    }
}

/// `run`, `ps`, `logs`, `exec`, `stop` and `rm`: containers, which need
/// jails.
#[cfg(unix)]
async fn containers(cli: &Cli) -> Result<()> {
    use futures::StreamExt;
    use jailer::runtime::{
        LABEL_IP, LABEL_POD, LABEL_PORTS, LABEL_ROLE, LINUX_MODULES, Mount, Network, RunSpec,
    };
    use std::time::Duration;

    use legion_runtime::{Output, Runtime};

    match &cli.command {
        Commands::Run {
            rm,
            detach,
            interactive,
            tty,
            name,
            env,
            volumes,
            user,
            workdir,
            hostname,
            entrypoint,
            vnet,
            network,
            publish,
            allow_mlock,
            sysv,
            params,
            limits,
            linux,
            args,
        } => {
            require_root("run")?;
            let (sys, store, runtime) = open_context(cli, *linux)?;
            let (image_ref, cmd_args) = match args.split_first() {
                Some((img, rest)) => (img.clone(), rest.to_vec()),
                None => (default_local_image_for_cwd(), Vec::new()),
            };

            // Pull automatically if the image is not in the local store and not a localhost ref.
            if store.find(&image_ref)?.is_none() {
                let r = Reference::parse(&image_ref)?;
                if !r.is_local() {
                    let creds = resolve_credentials(&r.registry, None, None)?;
                    println!("Pulling {r}...");
                    store.pull(&image_ref, creds.as_ref(), "root").await?;
                }
            }
            let image = store
                .find(&image_ref)?
                .with_context(|| format!("{image_ref}: image not known"))?;
            if image.config.os == "linux" {
                if !*linux {
                    bail!(
                        "{image_ref} is a Linux image; pass --linux to run it through FreeBSD's Linux ABI"
                    );
                }
                for m in LINUX_MODULES {
                    let _ = sys.kld_load(m);
                }
            }

            let mut env_map = BTreeMap::new();
            for kv in env {
                let (k, v) = kv
                    .split_once('=')
                    .with_context(|| format!("-e {kv:?} must be KEY=VALUE"))?;
                env_map.insert(k.to_owned(), v.to_owned());
            }

            let mut mounts = Vec::new();
            for vol in volumes {
                let parts: Vec<&str> = vol.split(':').collect();
                let (src, dst, ro) = match parts.as_slice() {
                    [s, d] => (*s, *d, false),
                    [s, d, opt] => (*s, *d, *opt == "ro"),
                    _ => bail!("invalid volume mount {vol:?} (expected SRC:DEST[:ro])"),
                };
                mounts.push(Mount::nullfs(src, dst, ro));
            }

            let mut extra_params = Vec::new();
            for kv in params {
                let (k, v) = kv.split_once('=').unwrap_or((kv.as_str(), ""));
                extra_params.push((k.to_owned(), v.to_owned()));
            }

            let ports = publish
                .iter()
                .map(|p| p.parse())
                .collect::<Result<Vec<jailer::net::Port>, _>>()?;
            let network = match network {
                NetworkArg::Host if *vnet || !ports.is_empty() => Network::Bridge,
                NetworkArg::Host => Network::Host,
                NetworkArg::Bridge => Network::Bridge,
                NetworkArg::None if *vnet || !ports.is_empty() => {
                    bail!("--network none has no ports to publish and is not --vnet's bridge")
                }
                NetworkArg::None => Network::None,
            };
            let leases = jailer::net::Leases::new(jailer::net::LEASES);

            // When running in foreground without `-d`, default to removing the
            // ephemeral test container afterwards unless `--name` was given to keep it.
            let auto_rm = *rm || (!*detach && name.is_none());
            let name = name.clone().unwrap_or_else(|| {
                let mut b = [0u8; 6];
                getrandom::fill(&mut b).expect("random bytes");
                b.iter()
                    .fold("jailer-".to_owned(), |n, x| n + &format!("{x:02x}"))
            });
            let spec = RunSpec {
                name,
                image: image.references[0].clone(),
                entrypoint: entrypoint.iter().cloned().collect(),
                command: cmd_args,
                env: env_map,
                user: user.clone(),
                work_dir: workdir.clone(),
                hostname: hostname.clone(),
                mounts,
                params: extra_params,
                network,
                ports,
                allow_mlock: *allow_mlock,
                sysv: sysv.clone(),
                limits: limits.parse()?,
            };

            let id = jailer::runtime::create(&runtime, &*sys, &leases, &spec).await?;
            if *detach {
                if let Err(e) = runtime.start(&id).await {
                    if *rm {
                        let _ = jailer::runtime::remove(&runtime, &*sys, &leases, &id).await;
                    }
                    return Err(e.into());
                }
                println!("{id}");
                return Ok(());
            }
            let code = runtime.run_attached(&id, *interactive, *tty).await;
            if auto_rm {
                let _ = jailer::runtime::remove(&runtime, &*sys, &leases, &id).await;
            }
            let code = code?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }

        Commands::Ps { all } => {
            let (_, _, runtime) = open_context(cli, true)?;
            let all_of = runtime.list(&[]).await?;
            // A member's address and ports are its pod's.
            let network = |c: &legion_runtime::ContainerSummary| {
                let pod = c.labels.get(LABEL_POD)?;
                let labels = &all_of.iter().find(|p| &p.id == pod)?.labels;
                let mut net = labels.get(LABEL_IP)?.clone();
                if let Some(ports) = labels.get(LABEL_PORTS) {
                    net = format!("{net} {}", ports.replace(',', " "));
                }
                Some(net)
            };
            let mut list = Vec::new();
            for c in &all_of {
                if c.labels.get(LABEL_ROLE).is_some_and(|r| r == "pod")
                    || (!*all && c.state != "running")
                {
                    continue;
                }
                let status = match c.state.as_str() {
                    "running" => {
                        let jid = runtime.inspect(&c.id).await?.state.jid;
                        format!("running (jid {jid}, pid {})", c.pid)
                    }
                    "exited" => format!("exited ({})", c.exit_code),
                    other => other.to_owned(),
                };
                list.push((c, status, network(c).unwrap_or_default()));
            }
            let width = |f: fn(&legion_runtime::ContainerSummary) -> &str, head: &str| {
                list.iter()
                    .map(|(c, ..)| f(c).len())
                    .chain([head.len()])
                    .max()
                    .unwrap_or(0)
            };
            let wn = width(|c| c.name(), "NAME");
            let wi = width(|c| &c.image, "IMAGE");
            let ws = list
                .iter()
                .map(|(_, s, _)| s.len())
                .chain(["STATUS".len()])
                .max()
                .unwrap_or(0);
            println!(
                "{:<14} {:<wn$}  {:<wi$}  {:<ws$}  NETWORK",
                "CONTAINER ID", "NAME", "IMAGE", "STATUS"
            );
            for (c, status, net) in &list {
                let short_id: String = c.id.chars().take(12).collect();
                let line = format!(
                    "{:<14} {:<wn$}  {:<wi$}  {status:<ws$}  {net}",
                    short_id,
                    c.name(),
                    c.image
                );
                println!("{}", line.trim_end());
            }
            Ok(())
        }

        Commands::Logs { tail, container } => {
            let (_, _, runtime) = open_context(cli, true)?;
            use std::io::Write;
            let id = runtime.find(container)?;
            let mut chunks = runtime.logs(&id, false, *tail).await?;
            while let Some(chunk) = chunks.next().await {
                let chunk = chunk?;
                match chunk.stream {
                    Output::Stdout => std::io::stdout().write_all(&chunk.data)?,
                    Output::Stderr => std::io::stderr().write_all(&chunk.data)?,
                }
            }
            Ok(())
        }

        Commands::Exec {
            interactive,
            tty,
            container,
            command,
        } => {
            require_root("exec")?;
            let (_, _, runtime) = open_context(cli, true)?;
            let id = runtime.find(container)?;
            let code = runtime
                .exec_inherit(&id, command, *interactive, *tty)
                .await?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }

        Commands::Stop { time, container } => {
            let (sys, _, runtime) = open_context(cli, true)?;
            let leases = jailer::net::Leases::new(jailer::net::LEASES);
            let id = runtime.find(container)?;
            let wait = Duration::from_secs(time.unwrap_or(10));
            jailer::runtime::stop(&runtime, &*sys, &leases, &id, wait).await?;
            println!("{container}");
            Ok(())
        }

        Commands::Rm { force, containers } => {
            let (sys, _, runtime) = open_context(cli, true)?;
            let leases = jailer::net::Leases::new(jailer::net::LEASES);
            for c in containers {
                let id = runtime.find(c)?;
                if !force && runtime.inspect(&id).await?.state.running {
                    bail!("container {c:?} is running: stop it first or use `rm -f`");
                }
                jailer::runtime::remove(&runtime, &*sys, &leases, &id).await?;
                println!("{c}");
            }
            Ok(())
        }

        _ => unreachable!("not a container command"),
    }
}

#[cfg(not(unix))]
async fn containers(_: &Cli) -> Result<()> {
    bail!("containers run in jails, which need FreeBSD")
}
