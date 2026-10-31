use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use jailer::auth::{resolve_credentials, save_credentials};
use jailer::build::{BuildBackend, BuildOptions};
use jailer::check::{CheckReport, Severity, check_containerfile, check_image};
use jailer::containerfile::Containerfile;
use jailer::init::{InitOptions, Template, detect_app_name};
use jailer::log::Output;
use jailer::registry::Client;
use jailer::runtime::{JailRuntime, RunSpec, RuntimeConfig};
use jailer::state::Mount;
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

        /// Create a VNET jail with an isolated network stack
        #[arg(long)]
        vnet: bool,

        /// Allow mlock(2) inside the jail (`org.freebsd.jail.allow.mlock=true`)
        #[arg(long)]
        allow_mlock: bool,

        /// Enable SysV IPC namespaces (`msg`, `sem`, `shm`)
        #[arg(long, value_delimiter = ',')]
        sysv: Vec<String>,

        /// Additional raw jail(8) parameters (KEY=VALUE)
        #[arg(long = "param", value_name = "KEY=VALUE")]
        params: Vec<String>,

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

/// Jails can only be created or entered by root; fail before pulling anything.
fn require_root(what: &str) -> Result<()> {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        bail!("`jailer {what}` needs root to create jails; run it with sudo or doas");
    }
    #[cfg(not(unix))]
    let _ = what;
    Ok(())
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
    if unsafe { libc::geteuid() } == 0 && sys.zfs_available() {
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
        Store::open(sys.clone(), images_zfs.as_deref(), &images_dir, client)?.with_linux(linux),
    );
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("jailer"));
    let runtime = JailRuntime::new(
        sys.clone(),
        store.clone(),
        RuntimeConfig {
            state_dir: state_dir.join("containers"),
            dataset: jails_zfs,
            shim: vec![exe.into_os_string(), OsString::from("jail-shim")],
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
            allow_mlock,
            sysv,
            params,
            linux,
            args,
        } => {
            require_root("run")?;
            let (_, store, runtime) = open_context(&cli, *linux)?;
            let (image_ref, cmd_args) = match args.split_first() {
                Some((img, rest)) => (img.clone(), rest.to_vec()),
                None => (default_local_image_for_cwd(), Vec::new()),
            };

            // Pull automatically if the image is not in the local store and not a localhost ref.
            if store.get(&image_ref)?.is_none() {
                let r = Reference::parse(&image_ref)?;
                if !r.is_local() {
                    let creds = resolve_credentials(&r.registry, None, None)?;
                    println!("Pulling {r}...");
                    store.pull(&image_ref, creds.as_ref(), "root").await?;
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
                mounts.push(Mount {
                    source: src.to_owned(),
                    destination: dst.to_owned(),
                    read_only: ro,
                });
            }

            let mut extra_params = Vec::new();
            for kv in params {
                let (k, v) = kv.split_once('=').unwrap_or((kv.as_str(), ""));
                extra_params.push((k.to_owned(), v.to_owned()));
            }

            // When running in foreground without `-d`, default to removing the
            // ephemeral test container afterwards unless `--name` was given to keep it.
            let auto_rm = *rm || (!*detach && name.is_none());

            let spec = RunSpec {
                name: name.clone(),
                image: image_ref,
                entrypoint: entrypoint.iter().cloned().collect(),
                command: cmd_args,
                env: env_map,
                user: user.clone(),
                work_dir: workdir.clone(),
                hostname: hostname.clone(),
                mounts,
                params: extra_params,
                stop_timeout: None,
                vnet: *vnet,
                allow_mlock: *allow_mlock,
                sysv: sysv.clone(),
                linux: *linux,
                rm: auto_rm,
                detach: *detach,
                interactive: *interactive,
                tty: *tty,
            };

            let (id, code) = runtime.run(&spec).await?;
            if *detach {
                println!("{id}");
                Ok(())
            } else {
                if code != 0 {
                    std::process::exit(code);
                }
                Ok(())
            }
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
                    if store.get(only)?.is_some() {
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
            let img = store.export(&image_ref, &out_path, name.as_deref())?;
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
            if let Some(img) = store.get(&img_lookup)? {
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

        Commands::Rmi { reference } => {
            let (_, store, _) = open_context(&cli, true)?;
            if store.remove(reference).await? {
                println!("Removed {reference}");
            } else {
                bail!("image {reference:?} not found");
            }
            Ok(())
        }

        Commands::Ps { all } => {
            let (_, _, runtime) = open_context(&cli, true)?;
            let list = runtime.list(*all)?;
            let width = |f: fn(&jailer::runtime::ContainerSummary) -> &str, head: &str| {
                list.iter()
                    .map(|c| f(c).len())
                    .chain([head.len()])
                    .max()
                    .unwrap_or(0)
            };
            let wn = width(|c| &c.name, "NAME");
            let wi = width(|c| &c.image, "IMAGE");
            println!(
                "{:<14} {:<wn$}  {:<wi$}  STATUS",
                "CONTAINER ID", "NAME", "IMAGE"
            );
            for c in list {
                let short_id: String = c.id.chars().take(12).collect();
                let st = match &c.status {
                    jailer::runtime::Status::Created => "created".to_owned(),
                    jailer::runtime::Status::Running(r) => {
                        format!("running (jid {}, pid {})", r.jid, r.pid)
                    }
                    jailer::runtime::Status::Exited(e) => format!("exited ({})", e.code),
                };
                println!("{:<14} {:<wn$}  {:<wi$}  {st}", short_id, c.name, c.image);
            }
            Ok(())
        }

        Commands::Logs { tail, container } => {
            let (_, _, runtime) = open_context(&cli, true)?;
            use std::io::Write;
            for chunk in runtime.logs(container, *tail)? {
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
            let (_, _, runtime) = open_context(&cli, true)?;
            let code = runtime.exec(container, command, *interactive, *tty).await?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }

        Commands::Stop { time, container } => {
            let (_, _, runtime) = open_context(&cli, true)?;
            runtime
                .stop(container, time.map(Duration::from_secs))
                .await?;
            println!("{container}");
            Ok(())
        }

        Commands::Rm { force, containers } => {
            let (_, _, runtime) = open_context(&cli, true)?;
            for c in containers {
                if !force {
                    let rec = runtime.record(c)?;
                    if matches!(runtime.status(&rec)?, jailer::runtime::Status::Running(_)) {
                        bail!("container {c:?} is running: stop it first or use `rm -f`");
                    }
                }
                runtime.remove(c).await?;
                println!("{c}");
            }
            Ok(())
        }
    }
}
