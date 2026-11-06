//! `jailer build`: builds a FreeBSD OCI image from a `Containerfile`, either
//! natively in Rust (running `RUN` steps in ephemeral FreeBSD jails and
//! diffing layers) or via `buildah` when `--backend buildah` is selected,
//! followed by Legion compatibility verification.

use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use clap::ValueEnum;

use crate::check::{CheckReport, check_containerfile, check_image};
use crate::containerfile::{
    self, Containerfile, CopySpec, IgnoreMatcher, Instruction, RunMount, RunOptions, Sharing,
    expand_vars, expand_word, glob_match,
};
use crate::layer::{self, TreeState};
use crate::oci::{self, Descriptor, History, ImageConfig};
use crate::registry::{Credentials, sha256};
use crate::runtime::{JailRuntime, Step, StepMount, StepNetwork};
use crate::store::{CachedLayer, CachedStep, Image, Pin, StorageMode, Store, chain_ids, hex_of};
use crate::{Error, Reference, users};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum BuildBackend {
    /// Self-contained Rust builder using FreeBSD jails and OCI layer diffing.
    #[default]
    Native,
    /// Delegate image construction to `buildah bud --network host`, then import.
    Buildah,
}

#[derive(Debug, Clone)]
pub struct BuildOptions {
    pub context_dir: PathBuf,
    pub containerfile: Option<PathBuf>,
    pub tag: String,
    pub build_args: BTreeMap<String, String>,
    pub target: Option<String>,
    pub backend: BuildBackend,
    /// Credentials, looked up for the registry of each image pulled.
    pub creds: crate::auth::CredsSource,
    pub strict_lint: bool,
    /// Run every step instead of reusing cached `RUN` results.
    pub no_cache: bool,
    /// Flatten the image, base included, into one layer.
    pub squash: bool,
    /// After the build, trim the build cache to this many bytes.
    pub cache_max: Option<u64>,
    /// Contents of the secrets `RUN --mount=type=secret` can mount, by id.
    pub secrets: BTreeMap<String, Vec<u8>>,
    /// SSH agent sockets `RUN --mount=type=ssh` can reach, by id.
    pub ssh: BTreeMap<String, PathBuf>,
    /// More jail(8) parameters for `RUN` steps, over the steps' own.
    pub jail_params: Vec<(String, String)>,
    /// Labels set on the image, over the Containerfile's.
    pub labels: BTreeMap<String, String>,
    /// The image's creation time, in seconds since 1970; none leaves it out,
    /// so that the same build gives the same image.
    pub timestamp: Option<i64>,
    /// Limits on each `RUN` step's jail.
    pub limits: crate::runtime::Limits,
    /// How new layers are compressed.
    pub compression: layer::Compression,
    /// The CPUs `RUN` steps may run on, as `cpuset -l` takes them.
    pub cpuset: Option<String>,
    /// Annotations for the image's manifest.
    pub annotations: BTreeMap<String, String>,
    /// Registry caches `RUN` steps may come from (`--cache-from`).
    pub cache_from: Vec<crate::cache::Remote>,
    /// Where to push this build's `RUN` steps (`--cache-to`).
    pub cache_to: Option<crate::cache::Remote>,
}

#[derive(Debug, Clone)]
pub struct BuildResult {
    pub image: Image,
    pub report: CheckReport,
}

struct BuiltStage {
    name: Option<String>,
    root: PathBuf,
    /// With a ZFS store, the dataset mounted on `root`, which later stages
    /// built on this one are cloned from.
    dataset: Option<String>,
    config: ImageConfig,
    layers: Vec<String>,
    descriptors: Vec<Descriptor>,
    /// Whether this stage gave a `CMD`, which a later `ENTRYPOINT` keeps;
    /// one from the base it resets, as in Docker.
    cmd_set: bool,
    /// Identifies the stage's filesystem so far, for the build cache.
    cache_key: String,
    /// The root's state after the last diff, so the next one hashes only
    /// what changed.
    tree: Option<TreeState>,
    /// The variables in scope at the stage's end, which a stage built on it
    /// starts with, its `ARG`s among them.
    vars: BTreeMap<String, String>,
}

/// Checks the stored `image` with its files, put together for it in the
/// store's temporary area and taken away again. An image whose files
/// cannot be put together fails: it is not passed on its config alone.
pub fn check_stored(store: &Store, image: &Image) -> Result<CheckReport, Error> {
    let tmp = tempfile::Builder::new()
        .prefix("check-root")
        .tempdir_in(store.dir().join("tmp"))?;
    if let Err(e) = store.prepare_rootfs(image, tmp.path(), None) {
        let _ = store.cleanup_rootfs(tmp.path(), None);
        return Err(Error::Build(format!(
            "preparing the files of {} to check them: {e}",
            image.references.first().unwrap_or(&image.id)
        )));
    }
    let report = check_image(&image.config, Some(tmp.path()));
    let _ = store.cleanup_rootfs(tmp.path(), None);
    Ok(report)
}

pub async fn build(
    store: &Arc<Store>,
    runtime: &JailRuntime,
    opts: &BuildOptions,
) -> Result<BuildResult, Error> {
    let cf_path = match &opts.containerfile {
        Some(p) => p.clone(),
        None => {
            let c1 = opts.context_dir.join("Containerfile");
            let c2 = opts.context_dir.join("Dockerfile");
            if c1.exists() {
                c1
            } else if c2.exists() {
                c2
            } else {
                return Err(Error::Build(format!(
                    "no Containerfile or Dockerfile found in {} (run `jailer init` to scaffold one)",
                    opts.context_dir.display()
                )));
            }
        }
    };

    let cf = Containerfile::parse_file(&cf_path)?;
    for w in &cf.warnings {
        eprintln!("warning: {w}");
    }
    let mut report = check_containerfile(&cf, opts.target.as_deref());

    if opts.backend == BuildBackend::Buildah {
        let image = build_with_buildah(store, &cf_path, opts).await?;
        if let Some(max) = opts.cache_max {
            crate::store::trim_cache(store, max).await?;
        }
        report.merge(check_stored(store, &image)?);
        if opts.strict_lint && report.has_errors() {
            return Err(Error::Build(
                "Legion compatibility check reported errors".to_owned(),
            ));
        }
        return Ok(BuildResult { image, report });
    }

    let ignore = IgnoreMatcher::from_context_dir(&opts.context_dir)?;
    let build_tmp = tempfile::Builder::new()
        .prefix("build")
        .tempdir_in(store.dir().join("tmp"))?;

    // Docker's automatic platform args, known to `FROM` and to an `ARG`
    // without a default. jailer builds for this host's platform only.
    let platform = format!("freebsd/{}", oci::arch());
    let predefined: BTreeMap<String, String> = [
        ("BUILDPLATFORM", platform.as_str()),
        ("TARGETPLATFORM", platform.as_str()),
        ("BUILDOS", "freebsd"),
        ("TARGETOS", "freebsd"),
        ("BUILDARCH", oci::arch()),
        ("TARGETARCH", oci::arch()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    let mut build_args = predefined.clone();
    build_args.extend(opts.build_args.clone());

    // A global ARG's default may name the ARGs before it.
    let mut global_vars = BTreeMap::new();
    let mut from_vars = predefined;
    for (k, def) in &cf.global_args {
        let v = match build_args.get(k) {
            Some(v) => Some(v.clone()),
            None => def.as_ref().map(|d| expand_word(d, &from_vars)),
        };
        if let Some(v) = v {
            global_vars.insert(k.clone(), v.clone());
            from_vars.insert(k.clone(), v);
        }
    }

    // Keeps the base images and new layers from a concurrent `rmi`.
    let pin = store.pin()?;
    let imported = if opts.no_cache || opts.cache_from.is_empty() {
        crate::cache::Imported::default()
    } else {
        crate::cache::Imported::read(store.client(), &opts.cache_from).await
    };
    let used = std::sync::Mutex::new(Vec::new());
    let env = BuildEnv {
        store,
        pin: &pin,
        opts,
        runtime,
        ignore: &ignore,
        build_args: &build_args,
        global_args: &global_vars,
        tmp_dir: build_tmp.path(),
        imported: &imported,
        used: &used,
    };
    let mut completed_stages: Vec<BuiltStage> = Vec::new();
    // With a ZFS store, stages are clones rather than copies: of the base
    // image's top layer, or of the stage they are built on. They are kept
    // beside the store's datasets, out of reach of its prune.
    let stage_datasets = match store.mode() {
        StorageMode::Zfs(images) => images.rsplit_once('/').map(|(root, _)| {
            let tmp = build_tmp.path().file_name().unwrap_or_default();
            (
                format!("{root}/build"),
                format!(
                    "{root}/build/{}-{}",
                    std::process::id(),
                    tmp.to_string_lossy()
                ),
            )
        }),
        StorageMode::Directory => None,
    };
    let mut cleanup_guard = StageCleanup {
        sys: store.sys().clone(),
        stages: Vec::new(),
        parent: None,
    };
    if let Some((build, mine)) = &stage_datasets {
        let sys = store.sys();
        sys.zfs_create(build, &[("mountpoint", "none")])?;
        sys.zfs_create(mine, &[("mountpoint", "none")])?;
        cleanup_guard.parent = Some(mine.clone());
    }

    for stage_def in &cf.stages {
        let base_ref = expand_word(&stage_def.base, &from_vars);
        if let Some(p) = &stage_def.platform {
            let p = expand_word(p, &from_vars);
            let mut parts = p.split('/');
            if parts.next() != Some("freebsd") || parts.next() != Some(oci::arch()) {
                return Err(Error::Build(format!(
                    "line {}: FROM --platform={p}: jailer builds for {platform}, this host's platform; build {p} images on such a host and combine them with `jailer manifest push`",
                    stage_def.line
                )));
            }
        }
        let stage_root = build_tmp.path().join(format!("stage-{}", stage_def.index));
        std::fs::create_dir_all(&stage_root)?;
        let dataset = stage_datasets
            .as_ref()
            .map(|(_, mine)| format!("{mine}/stage-{}", stage_def.index));
        cleanup_guard
            .stages
            .push((stage_root.clone(), dataset.clone()));
        let mountpoint = stage_root.to_string_lossy().into_owned();

        let mut built = if base_ref.eq_ignore_ascii_case("scratch") {
            if let Some(ds) = &dataset {
                store.sys().zfs_create(ds, &[("mountpoint", &mountpoint)])?;
            }
            BuiltStage {
                name: stage_def.name.clone(),
                root: stage_root,
                dataset,
                config: ImageConfig {
                    architecture: oci::arch().to_owned(),
                    os: "freebsd".to_owned(),
                    ..Default::default()
                },
                layers: Vec::new(),
                descriptors: Vec::new(),
                cmd_set: false,
                cache_key: root_key(opts, &["scratch"]),
                tree: None,
                vars: BTreeMap::new(),
            }
        } else if let Some(prev) = find_stage(&completed_stages, &base_ref) {
            match (&prev.dataset, &dataset) {
                (Some(from), Some(ds)) => {
                    // A stage is done with once built on: the snapshot
                    // holds it as it ended.
                    let snapshot = format!("{from}@stage-{}", stage_def.index);
                    store.sys().zfs_snapshot(&snapshot)?;
                    store
                        .sys()
                        .zfs_clone(&snapshot, ds, &[("mountpoint", &mountpoint)])?;
                }
                _ => layer::copy_tree(&prev.root, &stage_root)?,
            }
            BuiltStage {
                name: stage_def.name.clone(),
                root: stage_root,
                dataset,
                config: prev.config.clone(),
                layers: prev.layers.clone(),
                descriptors: prev.descriptors.clone(),
                cmd_set: false,
                cache_key: prev.cache_key.clone(),
                tree: None,
                vars: prev.vars.clone(),
            }
        } else {
            println!("Step 0/{}: FROM {base_ref}", stage_def.instructions.len());
            let base_img = match store.pin_image(&pin, &base_ref).await? {
                Some(img) => img,
                None => {
                    println!("Pulling base image {base_ref}...");
                    store
                        .pull(
                            &base_ref,
                            pull_creds(&opts.creds, &base_ref)?.as_ref(),
                            "root",
                        )
                        .await?;
                    store.pin_image(&pin, &base_ref).await?.ok_or_else(|| {
                        Error::Build(format!(
                            "base image {base_ref} was removed during the build"
                        ))
                    })?
                }
            };
            store.prepare_rootfs(&base_img, &stage_root, dataset.as_deref())?;
            let mut cfg = base_img.config.clone();
            if cfg.os.is_empty() {
                cfg.os = "freebsd".to_owned();
            }
            if cfg.architecture.is_empty() {
                cfg.architecture = oci::arch().to_owned();
            }
            BuiltStage {
                name: stage_def.name.clone(),
                root: stage_root,
                dataset,
                config: cfg,
                layers: base_img.layers.clone(),
                descriptors: base_img.layer_descriptors.clone(),
                cmd_set: false,
                cache_key: root_key(opts, &["from", &base_img.id]),
                tree: None,
                vars: BTreeMap::new(),
            }
        };

        // Seed `vars` with any ENV already present in the base image.
        let mut vars = std::mem::take(&mut built.vars);
        for kv in &built.config.config.env {
            if let Some((k, v)) = kv.split_once('=') {
                vars.insert(k.to_owned(), v.to_owned());
            }
        }

        let total = stage_def.instructions.len();
        // The base's ONBUILD triggers run first, and are not passed on.
        let triggers = std::mem::take(&mut built.config.config.on_build);
        for trigger in &triggers {
            println!("Step 0/{total}: ONBUILD {trigger}");
            let sp = containerfile::parse_trigger(trigger, stage_def.line)?;
            execute_instruction(env, &completed_stages, &mut built, &mut vars, &sp, 0).await?;
        }
        for (idx, sp) in stage_def.instructions.iter().enumerate() {
            let step_no = idx + 1;
            println!("Step {step_no}/{total}: {}", sp.raw);
            execute_instruction(env, &completed_stages, &mut built, &mut vars, sp, step_no).await?;
        }

        let reached_target = opts
            .target
            .as_ref()
            .is_some_and(|t| built.name.as_deref() == Some(t.as_str()));
        built.vars = vars;
        completed_stages.push(built);
        if reached_target {
            break;
        }
    }

    if let Some(target_name) = &opts.target
        && !completed_stages
            .iter()
            .any(|s| s.name.as_deref() == Some(target_name.as_str()))
    {
        return Err(Error::Build(format!(
            "target stage {target_name:?} not found in Containerfile"
        )));
    }

    let final_stage = completed_stages
        .pop()
        .ok_or_else(|| Error::Build("no stage built".to_owned()))?;

    // If the image ended up with 0 layers (e.g. `FROM scratch` with only metadata),
    // pack the rootfs so it has at least one layer for ZFS/Directory mounting.
    let mut final_config = final_stage.config;
    let mut final_layers = final_stage.layers;
    let mut final_descriptors = final_stage.descriptors;
    if opts.squash && !final_layers.is_empty() {
        final_layers.clear();
        final_descriptors.clear();
        final_config.rootfs.diff_ids.clear();
        for h in &mut final_config.history {
            h.empty_layer = true;
        }
        record_history(&mut final_config, "jailer build --squash", false);
    }
    if final_layers.is_empty() {
        let tar_out = build_tmp.path().join("scratch.tar");
        let gz_out = build_tmp.path().join("scratch.tar.gz");
        let art =
            layer::pack_directory_layer(&final_stage.root, &tar_out, &gz_out, opts.compression)?;
        final_config.rootfs.diff_ids.push(art.diff_id.clone());
        let chains = chain_ids(&final_config.rootfs.diff_ids);
        let chain_hex = hex_of(chains.last().unwrap())?.to_owned();
        let mut desc = store
            .commit_built_layer(&pin, None, &chain_hex, &tar_out, &gz_out, &art)
            .await?;
        desc.media_type = opts.compression.media_type().to_owned();
        final_layers.push(chain_hex);
        final_descriptors.push(desc);
    }

    final_config.config.labels.extend(opts.labels.clone());
    if let Some(secs) = opts.timestamp {
        let created = legion_api::clock::format(secs);
        // This build's history, not the base image's, takes its time.
        for h in final_config
            .history
            .iter_mut()
            .filter(|h| h.created.is_empty())
        {
            h.created.clone_from(&created);
        }
        final_config.created = created;
    }

    report.merge(check_image(&final_config, Some(&final_stage.root)));
    if opts.strict_lint && report.has_errors() {
        return Err(Error::Build(
            "Legion compatibility check reported errors".to_owned(),
        ));
    }

    let target_ref = Reference::parse_local_tag(&opts.tag)?;
    let image = store
        .register_built_image_with(
            &pin,
            &target_ref,
            final_config,
            final_layers,
            final_descriptors,
            opts.annotations.clone(),
        )
        .await?;
    if let Some(remote) = &opts.cache_to {
        let steps = std::mem::take(&mut *used.lock().unwrap());
        let digest = crate::cache::export(store.client(), store, remote, &steps).await?;
        println!(
            "Pushed the build cache ({} steps) to {}@{digest}",
            steps.len(),
            remote.reference
        );
    }
    drop(pin);
    if let Some(max) = opts.cache_max {
        crate::store::trim_cache(store, max).await?;
    }

    Ok(BuildResult { image, report })
}

/// Removes a build's stages, and with a ZFS store their datasets: the
/// last first, as each may be a clone of one before it.
struct StageCleanup {
    sys: Arc<dyn crate::sys::Sys>,
    stages: Vec<(PathBuf, Option<String>)>,
    /// The datasets' parent, this build's own.
    parent: Option<String>,
}

impl Drop for StageCleanup {
    fn drop(&mut self) {
        for (root, dataset) in self.stages.iter().rev() {
            if let Some(ds) = dataset
                && self.sys.zfs_list(ds).is_ok_and(|l| !l.is_empty())
            {
                let _ = self.sys.zfs_destroy(ds, true);
            }
            let _ = layer::remove_tree(root);
        }
        if let Some(ds) = &self.parent {
            let _ = self.sys.zfs_destroy(ds, true);
        }
    }
}

/// What every step of a build shares.
#[derive(Clone, Copy)]
struct BuildEnv<'a> {
    store: &'a Arc<Store>,
    pin: &'a Pin,
    opts: &'a BuildOptions,
    runtime: &'a JailRuntime,
    ignore: &'a IgnoreMatcher,
    /// `--build-arg` values over Docker's automatic ones.
    build_args: &'a BTreeMap<String, String>,
    /// The `ARG`s before the first `FROM`, as set: a stage sees one only
    /// through an `ARG` of its own naming it.
    global_args: &'a BTreeMap<String, String>,
    tmp_dir: &'a Path,
    /// Steps the `--cache-from` caches have.
    imported: &'a crate::cache::Imported,
    /// This build's `RUN` steps by cache key, for `--cache-to`.
    used: &'a std::sync::Mutex<Vec<(String, CachedStep)>>,
}

/// Extracts the image `name` (pulled if missing, pinned for the build) at
/// `at`, for `COPY --from` or `RUN --mount=type=bind,from=` naming an image
/// rather than a stage.
/// The credentials for pulling `name`, from its own registry.
fn pull_creds(creds: &crate::auth::CredsSource, name: &str) -> Result<Option<Credentials>, Error> {
    creds.for_registry(&Reference::parse(name)?.registry)
}

async fn extract_image(
    env: BuildEnv<'_>,
    name: &str,
    at: &Path,
    line: usize,
) -> Result<Image, Error> {
    let (store, pin) = (env.store, env.pin);
    let image = match store.pin_image(pin, name).await? {
        Some(img) => img,
        None => {
            println!("Pulling {name}...");
            store
                .pull(name, pull_creds(&env.opts.creds, name)?.as_ref(), "root")
                .await?;
            store.pin_image(pin, name).await?.ok_or_else(|| {
                Error::Build(format!(
                    "line {line}: image {name} was removed during the build"
                ))
            })?
        }
    };
    store.prepare_rootfs(&image, at, None)?;
    Ok(image)
}

/// A tree removed (file flags and all) when dropped.
struct TempTree(PathBuf);

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = layer::remove_tree(&self.0);
    }
}

fn find_stage<'a>(stages: &'a [BuiltStage], name_or_idx: &str) -> Option<&'a BuiltStage> {
    if let Ok(idx) = name_or_idx.parse::<usize>() {
        return stages.get(idx);
    }
    stages
        .iter()
        .find(|s| s.name.as_deref() == Some(name_or_idx))
}

async fn execute_instruction(
    env: BuildEnv<'_>,
    completed_stages: &[BuiltStage],
    stage: &mut BuiltStage,
    vars: &mut BTreeMap<String, String>,
    sp: &crate::containerfile::SpannedInstruction,
    step_no: usize,
) -> Result<(), Error> {
    let BuildEnv {
        store,
        pin,
        opts,
        runtime,
        ignore,
        build_args: cli_build_args,
        global_args,
        tmp_dir,
        ..
    } = env;
    let (no_cache, context_dir) = (opts.no_cache, opts.context_dir.as_path());
    match &sp.instruction {
        Instruction::Arg(args) => {
            for (name, default) in args {
                // An ENV of the same name goes over an ARG, before or after.
                let prefix = format!("{name}=");
                if stage
                    .config
                    .config
                    .env
                    .iter()
                    .any(|e| e.starts_with(&prefix))
                {
                    continue;
                }
                if let Some(val) = cli_build_args.get(name) {
                    vars.insert(name.clone(), val.clone());
                } else if let Some(def) = default {
                    let expanded = expand_word(def, vars);
                    vars.insert(name.clone(), expanded);
                } else if let Some(val) = global_args.get(name) {
                    vars.entry(name.clone()).or_insert_with(|| val.clone());
                }
            }
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Env(pairs) => {
            // Each value sees the variables as they were before this `ENV`.
            let before = vars.clone();
            for (k, v) in pairs {
                // As in Docker, the name is expanded too.
                let k = expand_word(k, &before);
                let expanded = expand_word(v, &before);
                vars.insert(k.clone(), expanded.clone());
                set_env(&mut stage.config.config.env, &k, &expanded);
            }
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Label(pairs) => {
            for (k, v) in pairs {
                let expanded = expand_word(v, vars);
                stage
                    .config
                    .config
                    .labels
                    .insert(expand_word(k, vars), expanded);
            }
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Workdir(wd) => {
            let new_wd = workdir_path(&stage.config.config.working_dir, &expand_word(wd, vars));
            // A directory it makes goes into a layer of its own, as in Docker,
            // owned by the `USER` in force.
            let dir = resolve_in_root(&stage.root, &new_wd, true)?;
            stage.config.config.working_dir = new_wd;
            if dir.is_dir() {
                record_history(&mut stage.config, &sp.raw, true);
            } else {
                let owner = match stage.config.config.user.as_str() {
                    "" => None,
                    user => {
                        let read = |f: &str| account_file(&stage.root, f);
                        let acc =
                            users::resolve(user, &read("passwd"), &read("group")).map_err(|e| {
                                Error::Build(format!(
                                    "line {}: WORKDIR as USER {user}: {e}",
                                    sp.line
                                ))
                            })?;
                        Some((acc.uid, acc.gid))
                    }
                };
                let before = TreeState::capture_from(&stage.root, stage.tree.as_ref())?;
                let mut made = Vec::new();
                let mut d = dir.as_path();
                while !d.exists() {
                    made.push(d.to_path_buf());
                    d = d.parent().unwrap_or(&stage.root);
                }
                std::fs::create_dir_all(&dir)?;
                if let Some((uid, gid)) = owner {
                    // As `COPY --chown` does: a build not run by root keeps
                    // them its own.
                    for d in &made {
                        apply_perms(d, Some((uid, gid)), Some(0o755))?;
                    }
                }
                commit_step_diff(env, stage, &before, step_no, &sp.raw).await?;
                stage.cache_key = copy_key(stage, &sp.raw);
            }
        }
        Instruction::User(u) => {
            stage.config.config.user = expand_word(u, vars);
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Expose(ports) => {
            for p in ports {
                let expanded = expand_word(p, vars);
                let key = if expanded.contains('/') {
                    expanded
                } else {
                    format!("{expanded}/tcp")
                };
                stage
                    .config
                    .config
                    .exposed_ports
                    .insert(key, serde_json::json!({}));
            }
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Volume(vols) => {
            for v in vols {
                let expanded = expand_word(v, vars);
                stage
                    .config
                    .config
                    .volumes
                    .insert(expanded, serde_json::json!({}));
            }
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Stopsignal(sig) => {
            stage.config.config.stop_signal = expand_word(sig, vars);
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Shell(sh) => {
            // Kept in the image, as Docker does, for the images built on it.
            stage
                .config
                .config
                .extra
                .insert("Shell".to_owned(), serde_json::json!(sh));
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Healthcheck(_) => {
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Onbuild(trigger) => {
            stage.config.config.on_build.push(trigger.clone());
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Entrypoint(form) => {
            stage.config.config.entrypoint = form.to_argv(&shell_of(&stage.config));
            if !stage.cmd_set {
                stage.config.config.cmd.clear();
            }
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Cmd(form) => {
            stage.config.config.cmd = form.to_argv(&shell_of(&stage.config));
            stage.cmd_set = true;
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Copy(spec) | Instruction::Add(spec) => {
            let is_add = matches!(sp.instruction, Instruction::Add(_));
            let spec = &CopySpec {
                from: spec.from.as_ref().map(|f| expand_word(f, vars)),
                ..spec.clone()
            };
            let extras = CopyExtras::prepare(spec, vars, tmp_dir, is_add, sp.line).await?;
            let from_image = match &spec.from {
                Some(name) if find_stage(completed_stages, name).is_none() => {
                    let tree = TempTree(tmp_dir.join(format!("from-{step_no}")));
                    extract_image(env, name, &tree.0, sp.line).await?;
                    Some(tree)
                }
                _ => None,
            };
            let before = TreeState::capture_from(&stage.root, stage.tree.as_ref())?;
            apply_copy(
                context_dir,
                ignore,
                completed_stages,
                from_image.as_ref().map(|t| t.0.as_path()),
                stage,
                vars,
                spec,
                is_add,
                &extras.files,
                tmp_dir,
                sp.line,
            )?;
            drop(from_image);
            drop(extras);
            commit_step_diff(env, stage, &before, step_no, &sp.raw).await?;
            stage.cache_key = copy_key(stage, &sp.raw);
        }
        Instruction::Run(form, run_opts) => {
            // As in Docker, `$VAR` in RUN, CMD and ENTRYPOINT is left to the
            // shell: build args and ENV reach it through the environment.
            let argv = form.to_argv(&shell_of(&stage.config));
            let mut run_env = stage.config.config.env.clone();
            for (k, v) in vars.iter() {
                if !run_env
                    .iter()
                    .any(|e| e.split('=').next() == Some(k.as_str()))
                {
                    run_env.push(format!("{k}={v}"));
                }
            }
            let mut mounts =
                RunMounts::prepare(env, completed_stages, vars, step_no, run_opts, sp.line).await?;
            for e in &mounts.env {
                let name = e.split('=').next().unwrap_or("");
                run_env.retain(|x| x.split('=').next() != Some(name));
                run_env.push(e.clone());
            }
            let key = next_key(
                &stage.cache_key,
                &[
                    "run",
                    &serde_json::to_string(&argv)?,
                    &serde_json::to_string(&run_env)?,
                    &stage.config.config.user,
                    &stage.config.config.working_dir,
                    &if opts.jail_params.is_empty() {
                        // As before there were any, so that keys stay.
                        mounts.key.clone()
                    } else {
                        format!(
                            "{} params={}",
                            mounts.key,
                            serde_json::to_string(&opts.jail_params)?
                        )
                    },
                ],
            );
            let mut cached = if no_cache {
                None
            } else {
                crate::store::cached_step(store, pin, &key).await?
            };
            if cached.is_none()
                && !no_cache
                && env
                    .imported
                    .fetch(
                        store,
                        pin,
                        &key,
                        &stage.config.rootfs.diff_ids,
                        stage.layers.last().map(String::as_str),
                        tmp_dir,
                    )
                    .await?
            {
                println!(" ---> From the registry cache");
                cached = crate::store::cached_step(store, pin, &key).await?;
            }
            match cached {
                Some(step) if apply_cached(store, stage, tmp_dir, step.layer.as_ref())? => {
                    println!(" ---> Using cache");
                    record_history(&mut stage.config, &sp.raw, step.layer.is_none());
                    env.used.lock().unwrap().push((key.clone(), step));
                }
                _ => {
                    // Said here, the jail call would fail less plainly.
                    #[cfg(unix)]
                    if unsafe { libc::geteuid() } != 0 {
                        return Err(Error::Build(format!(
                            "line {}: RUN needs root to create its jail; run `jailer build` with sudo or doas",
                            sp.line
                        )));
                    }
                    let before = TreeState::capture_from(&stage.root, stage.tree.as_ref())?;
                    mounts.place_ssh(&stage.root, sp.line)?;
                    let mut id = [0u8; 6];
                    getrandom::fill(&mut id).expect("random bytes");
                    let name: String = std::iter::once("jailer_build_".to_owned())
                        .chain(id.iter().map(|b| format!("{b:02x}")))
                        .collect();
                    let sys = &**store.sys();
                    // Taken away again however the step ends.
                    let limited = crate::runtime::limited(sys, &name, &opts.limits)?;
                    let code = runtime
                        .run_step(&Step {
                            name: &name,
                            root: &stage.root,
                            argv: &argv,
                            env: &run_env,
                            user: &stage.config.config.user,
                            work_dir: &stage.config.config.working_dir,
                            mounts: &mounts.mounts,
                            network: if run_opts.no_network {
                                StepNetwork::None
                            } else {
                                StepNetwork::Host
                            },
                            params: &opts.jail_params,
                            cpuset: opts.cpuset.as_deref(),
                        })
                        .await;
                    drop(limited);
                    let code = code?;
                    if code != 0 {
                        return Err(Error::Build(format!(
                            "RUN command {:?} exited with status {code}",
                            argv.join(" ")
                        )));
                    }
                    drop(mounts);
                    let layer = commit_step_diff(env, stage, &before, step_no, &sp.raw).await?;
                    let step = CachedStep { layer };
                    crate::store::record_step(store, &key, &step)?;
                    env.used.lock().unwrap().push((key.clone(), step));
                }
            }
            // What follows depends on what the step made, not only on what
            // it ran: a step run again may make something else.
            let top = stage.layers.last().map_or("", String::as_str);
            stage.cache_key = next_key(&key, &["after", top]);
        }
    }
    Ok(())
}

/// A `RUN` step's mounts, resolved to host paths, and what about them
/// belongs in the step's cache key. Temporary copies are removed on drop.
struct RunMounts {
    mounts: Vec<StepMount>,
    key: String,
    temp: Vec<PathBuf>,
    /// Variables the step gets, such as `SSH_AUTH_SOCK`.
    env: Vec<String>,
    /// SSH agents to give the step, placed by [`RunMounts::place_ssh`].
    ssh: Vec<SshMount>,
    /// Tasks relaying SSH agent connections, stopped on drop.
    relays: Vec<tokio::task::JoinHandle<()>>,
    /// Locks held on cache mounts shared `locked` or `private`.
    locks: Vec<std::fs::File>,
    /// What placing the agents made in the root: sockets, and the
    /// directories made for them. Removed on drop.
    placed: Vec<Placed>,
}

/// A socket or a directory [`RunMounts::place_ssh`] made, at `rel` in
/// `root`.
struct Placed {
    root: PathBuf,
    rel: PathBuf,
    dir: bool,
}

struct SshMount {
    agent: PathBuf,
    target: String,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl RunMounts {
    async fn prepare(
        env: BuildEnv<'_>,
        completed_stages: &[BuiltStage],
        vars: &BTreeMap<String, String>,
        step_no: usize,
        opts: &RunOptions,
        line: usize,
    ) -> Result<Self, Error> {
        let BuildEnv {
            store,
            ignore,
            tmp_dir,
            ..
        } = env;
        let (context_dir, secrets) = (env.opts.context_dir.as_path(), &env.opts.secrets);
        let mut out = RunMounts {
            mounts: Vec::new(),
            key: if opts.no_network {
                "network=none".to_owned()
            } else {
                String::new()
            },
            temp: Vec::new(),
            env: Vec::new(),
            ssh: Vec::new(),
            relays: Vec::new(),
            locks: Vec::new(),
            placed: Vec::new(),
        };
        let mounts: Vec<RunMount> = opts.mounts.iter().map(|m| m.expanded(vars)).collect();
        let caches = lock_caches(&mut out, store.dir(), &mounts, tmp_dir, step_no)?;
        for (i, m) in mounts.iter().enumerate() {
            let scratch = tmp_dir.join(format!("mount-{step_no}-{i}"));
            match m {
                RunMount::Cache {
                    id,
                    target,
                    read_only,
                    mode,
                    uid,
                    gid,
                    ..
                } => {
                    let dir = caches[&next_key("", &[id])].clone();
                    if !dir.exists() {
                        std::fs::create_dir_all(&dir)?;
                        set_owner_mode(&dir, *uid, *gid, *mode)?;
                    }
                    out.key.push_str(&format!("\0cache {id} {target}"));
                    // Options at their defaults leave the key as it was.
                    if *read_only {
                        out.key.push_str(" ro");
                    }
                    if (*mode, *uid, *gid) != (0o755, 0, 0) {
                        out.key
                            .push_str(&format!(" mode={mode:o} uid={uid} gid={gid}"));
                    }
                    out.mounts.push(StepMount::Nullfs {
                        source: dir,
                        target: target.clone(),
                        read_only: *read_only,
                    });
                }
                RunMount::Bind {
                    from,
                    source,
                    target,
                    rw,
                } => {
                    let from = from.clone();
                    let (root, origin) = match &from {
                        None => (context_dir.to_path_buf(), "context".to_owned()),
                        Some(name) => match find_stage(completed_stages, name) {
                            Some(st) => (st.root.clone(), st.cache_key.clone()),
                            None => {
                                let image_root = scratch.with_extension("image");
                                out.temp.push(image_root.clone());
                                let image = extract_image(env, name, &image_root, line).await?;
                                (image_root, format!("image {}", image.id))
                            }
                        },
                    };
                    let src = resolve_in_root(&root, source.trim_start_matches('/'), true)
                        .map_err(|e| Error::Build(format!("line {line}: {e}")))?;
                    let rel = src
                        .strip_prefix(context_dir)
                        .unwrap_or(&src)
                        .to_string_lossy()
                        .replace('\\', "/");
                    let not_found = || {
                        Error::Build(format!("line {line}: --mount source {source:?} not found"))
                    };
                    // A directory left out may have files put back, by `!`
                    // lines: the context has it, with only those.
                    let left_out = from.is_none() && ignore.is_ignored(&rel);
                    if std::fs::symlink_metadata(&src).is_err()
                        || (left_out && !(src.is_dir() && ignore.may_reinclude(&rel)))
                    {
                        return Err(not_found());
                    }
                    // As in Docker, the step does not see what .containerignore
                    // leaves out of the context, and `rw` writes are discarded:
                    // both mount a copy.
                    let filter = |p: &Path| {
                        let rel = rel_path(p, context_dir);
                        if !ignore.is_ignored(&rel) {
                            Keep::Yes
                        } else if ignore.may_reinclude(&rel) {
                            Keep::Below
                        } else {
                            Keep::No
                        }
                    };
                    let src = if left_out {
                        let copier = Copier::new(&scratch, None, None, false);
                        copier.below(&src, &scratch, &filter)?;
                        copier.finish()?;
                        // None of the files put back is there.
                        if std::fs::symlink_metadata(&scratch).is_err() {
                            return Err(not_found());
                        }
                        out.temp.push(scratch.clone());
                        scratch
                    } else if from.is_none()
                        && src.is_dir()
                        && any_ignored(context_dir, &src, ignore)
                    {
                        let copier = Copier::new(&scratch, None, None, false);
                        copier.dir(&src, &scratch, &filter)?;
                        copier.finish()?;
                        out.temp.push(scratch.clone());
                        scratch
                    } else if *rw {
                        if src.is_dir() {
                            layer::copy_tree(&src, &scratch)?;
                        } else {
                            std::fs::copy(&src, &scratch)?;
                        }
                        out.temp.push(scratch.clone());
                        scratch
                    } else {
                        src
                    };
                    // A stage or image is named by its id; context files by
                    // their contents.
                    let contents = if from.is_some() {
                        origin
                    } else {
                        content_digest(&src)?
                    };
                    out.key
                        .push_str(&format!("\0bind {source} {target} {rw} {contents}"));
                    out.mounts.push(StepMount::Nullfs {
                        source: src,
                        target: target.clone(),
                        read_only: !rw,
                    });
                }
                RunMount::Secret {
                    id,
                    target,
                    required,
                    mode,
                    uid,
                    gid,
                } => {
                    let Some(value) = secrets.get(id) else {
                        if *required {
                            return Err(Error::Build(format!(
                                "line {line}: secret {id:?} is required: give `--secret id={id},src=<file>`"
                            )));
                        }
                        continue;
                    };
                    write_private(&scratch, value)?;
                    out.temp.push(scratch.clone());
                    set_owner_mode(&scratch, *uid, *gid, *mode)?;
                    // Not the value: a key may be shared in a registry cache.
                    out.key.push_str(&format!("\0secret {id} {target}"));
                    if (*mode, *uid, *gid) != (0o400, 0, 0) {
                        out.key
                            .push_str(&format!(" mode={mode:o} uid={uid} gid={gid}"));
                    }
                    out.mounts.push(StepMount::Nullfs {
                        source: scratch,
                        target: target.clone(),
                        read_only: true,
                    });
                }
                RunMount::Tmpfs { target, size } => {
                    out.key.push_str(&format!("\0tmpfs {target}"));
                    // The step may look at how much room it has.
                    if let Some(size) = size {
                        out.key.push_str(&format!(" size={size}"));
                    }
                    out.mounts.push(StepMount::Tmpfs {
                        target: target.clone(),
                        size: *size,
                    });
                }
                RunMount::Ssh {
                    id,
                    target,
                    required,
                    mode,
                    uid,
                    gid,
                } => {
                    let Some(agent) = env.opts.ssh.get(id) else {
                        if *required {
                            return Err(Error::Build(format!(
                                "line {line}: SSH agent {id:?} is required: give `--ssh {id}`"
                            )));
                        }
                        continue;
                    };
                    if !target.rsplit_once('/').is_some_and(|(_, n)| !n.is_empty()) {
                        return Err(Error::Build(format!(
                            "line {line}: ssh mount target {target:?}: give a socket path"
                        )));
                    }
                    out.key.push_str(&format!("\0ssh {id} {target}"));
                    if (*mode, *uid, *gid) != (0o600, 0, 0) {
                        out.key
                            .push_str(&format!(" mode={mode:o} uid={uid} gid={gid}"));
                    }
                    out.env.push(format!("SSH_AUTH_SOCK={target}"));
                    out.ssh.push(SshMount {
                        agent: agent.clone(),
                        target: target.clone(),
                        mode: *mode,
                        uid: *uid,
                        gid: *gid,
                    });
                }
            }
        }
        Ok(out)
    }
}

/// Locks each cache `mounts` use, once however many of them name it and
/// in the order of their names, so that a step cannot wait for itself nor
/// two builds for each other: shared for `sharing=shared`, else alone,
/// as the strictest mount of it asks. `prune --cache` leaves a cache that
/// is held. Returns each cache's directory by name: a `private` one in use
/// elsewhere is an empty one of this step's.
fn lock_caches(
    out: &mut RunMounts,
    store_dir: &Path,
    mounts: &[RunMount],
    tmp_dir: &Path,
    step_no: usize,
) -> Result<BTreeMap<String, PathBuf>, Error> {
    let strictness = |s: Sharing| match s {
        Sharing::Shared => 0,
        Sharing::Private => 1,
        Sharing::Locked => 2,
    };
    let mut wanted: BTreeMap<String, (&str, Sharing)> = BTreeMap::new();
    for m in mounts {
        if let RunMount::Cache { id, sharing, .. } = m {
            let w = wanted
                .entry(next_key("", &[id]))
                .or_insert((id.as_str(), *sharing));
            if strictness(*sharing) > strictness(w.1) {
                w.1 = *sharing;
            }
        }
    }
    let caches = store_dir.join("run-cache");
    let mut dirs = BTreeMap::new();
    for (name, (id, sharing)) in wanted {
        std::fs::create_dir_all(&caches)?;
        let mut dir = caches.join(&name);
        let lock = std::fs::File::create(caches.join(format!("{name}.lock")))?;
        let shared = sharing == Sharing::Shared;
        let tried = if shared {
            lock.try_lock_shared()
        } else {
            lock.try_lock()
        };
        match tried {
            Ok(()) => out.locks.push(lock),
            // Another build has it: this one gets its own.
            Err(std::fs::TryLockError::WouldBlock) if sharing == Sharing::Private => {
                dir = tmp_dir.join(format!("cache-{step_no}-{name}"));
                out.temp.push(dir.clone());
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                println!(" ---> Waiting for cache {id:?}, in use by another build");
                if shared {
                    lock.lock_shared()?;
                } else {
                    lock.lock()?;
                }
                out.locks.push(lock);
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        dirs.insert(name, dir);
    }
    Ok(dirs)
}

impl RunMounts {
    /// Puts a socket relaying each SSH agent at its target in `root`, for
    /// the step only: nullfs mounts files and directories, not sockets, and
    /// a directory mounted for one would hide what the image has there.
    /// Called once the tree before the step is taken, so that neither the
    /// socket nor a directory made for it is in the step's layer.
    fn place_ssh(&mut self, root: &Path, line: usize) -> Result<(), Error> {
        for m in std::mem::take(&mut self.ssh) {
            let (dir, name) = m.target.rsplit_once('/').unwrap_or(("", &m.target));
            let dir = resolve_in_root(root, dir.trim_start_matches('/'), true)
                .map_err(|e| Error::Build(format!("line {line}: {e}")))?;
            let mut missing = Vec::new();
            let mut d = dir.as_path();
            while std::fs::symlink_metadata(d).is_err() {
                missing.push(d.to_path_buf());
                d = d.parent().unwrap_or(root);
            }
            std::fs::create_dir_all(&dir)?;
            let sock = dir.join(name);
            let relay = if std::fs::symlink_metadata(&sock).is_ok() {
                Err(Error::Build(format!(
                    "line {line}: ssh mount target {:?} is already in the image",
                    m.target
                )))
            } else {
                relay_ssh_agent(&dir, name, &m.agent, line)
            };
            let placed = |p: &Path, dir: bool| Placed {
                root: root.to_path_buf(),
                rel: p.strip_prefix(root).unwrap_or(p).to_path_buf(),
                dir,
            };
            let made: Vec<Placed> = missing.iter().map(|d| placed(d, true)).collect();
            match relay {
                Ok(r) => {
                    self.relays.push(r);
                    self.placed.push(placed(&sock, false));
                    self.placed.extend(made);
                }
                Err(e) => {
                    self.placed.extend(made);
                    return Err(e);
                }
            }
            set_owner_mode(&sock, m.uid, m.gid, m.mode)?;
        }
        Ok(())
    }
}

impl Drop for RunMounts {
    fn drop(&mut self) {
        for r in &self.relays {
            r.abort();
        }
        // The sockets first, then the directories made for them, deepest
        // first: two mounts may share one. A directory the step put
        // something in stays, in its layer. The step ran as root in the
        // tree: whatever links it left there are not followed.
        let (mut dirs, socks): (Vec<_>, Vec<_>) = self.placed.iter().partition(|p| p.dir);
        for p in socks {
            let _ = remove_beneath(&p.root, &p.rel, false);
        }
        dirs.sort_by_key(|p| std::cmp::Reverse(p.rel.components().count()));
        for p in dirs {
            let _ = remove_beneath(&p.root, &p.rel, true);
        }
        for p in &self.temp {
            let _ = layer::remove_tree(p);
        }
    }
}

/// Removes the socket (or with `dir`, the empty directory) at `rel` in
/// `root`, going down from `root` one directory at a time and through no
/// link: one a step put in its path does not take the removal out of the
/// tree. Whatever is there but a socket, or a directory, stays.
#[cfg(unix)]
fn remove_beneath(root: &Path, rel: &Path, dir: bool) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let parts: Vec<&std::ffi::OsStr> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();
    let Some((last, parents)) = parts.split_last() else {
        return Ok(());
    };
    let c = |s: &[u8]| {
        CString::new(s).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
    };
    let open = |at: libc::c_int, name: &CString, flags: libc::c_int| {
        // SAFETY: a valid C string; the descriptor is owned from here.
        let fd = unsafe {
            libc::openat(
                at,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | flags,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` was just opened, and nothing else owns it.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    };
    let mut at = open(libc::AT_FDCWD, &c(root.as_os_str().as_bytes())?, 0)?;
    for p in parents {
        at = open(at.as_raw_fd(), &c(p.as_bytes())?, libc::O_NOFOLLOW)?;
    }
    let name = c(last.as_bytes())?;
    if !dir {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `st` is written by fstatat before it is read.
        let found = unsafe {
            libc::fstatat(
                at.as_raw_fd(),
                name.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if found != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fstatat succeeded.
        if unsafe { st.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            return Ok(());
        }
    }
    let flags = if dir { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: a valid descriptor and C string.
    if unsafe { libc::unlinkat(at.as_raw_fd(), name.as_ptr(), flags) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn remove_beneath(root: &Path, rel: &Path, dir: bool) -> std::io::Result<()> {
    let p = root.join(rel);
    if dir {
        std::fs::remove_dir(p)
    } else {
        std::fs::remove_file(p)
    }
}

/// Listens at `name` in `dir` and passes each connection on to the SSH
/// agent at `agent`.
#[cfg(unix)]
fn relay_ssh_agent(
    dir: &Path,
    name: &str,
    agent: &Path,
    line: usize,
) -> Result<tokio::task::JoinHandle<()>, Error> {
    let listener = bind_socket(dir, name)
        .and_then(|l| {
            l.set_nonblocking(true)?;
            tokio::net::UnixListener::from_std(l)
        })
        .map_err(|e| Error::Build(format!("line {line}: ssh mount: {e}")))?;
    let agent = agent.to_path_buf();
    Ok(tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let agent = agent.clone();
            tokio::spawn(async move {
                if let Ok(mut up) = tokio::net::UnixStream::connect(&agent).await {
                    let _ = tokio::io::copy_bidirectional(&mut conn, &mut up).await;
                }
            });
        }
    }))
}

/// A socket listening at `name` in `dir`, bound there by `bindat(2)`: a
/// path in a stage's root may be longer than a socket address holds.
#[cfg(target_os = "freebsd")]
fn bind_socket(dir: &Path, name: &str) -> std::io::Result<std::os::unix::net::UnixListener> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        fn bindat(
            fd: libc::c_int,
            s: libc::c_int,
            addr: *const libc::sockaddr,
            len: libc::socklen_t,
        ) -> libc::c_int;
    }
    let last = std::io::Error::last_os_error;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
    // SAFETY: plain system calls on a valid path and address, and on
    // descriptors owned here from the moment they are made.
    unsafe {
        let d = libc::open(c.as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC);
        if d < 0 {
            return Err(last());
        }
        let d = OwnedFd::from_raw_fd(d);
        let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            return Err(last());
        }
        let s = OwnedFd::from_raw_fd(s);
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = name.as_bytes();
        if bytes.len() >= addr.sun_path.len() {
            return Err(std::io::Error::other(format!(
                "socket name {name:?} is too long"
            )));
        }
        for (dst, b) in addr.sun_path.iter_mut().zip(bytes) {
            *dst = *b as libc::c_char;
        }
        let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        if bindat(d.as_raw_fd(), s.as_raw_fd(), (&raw const addr).cast(), len) != 0
            || libc::listen(s.as_raw_fd(), 128) != 0
        {
            return Err(last());
        }
        Ok(std::os::unix::net::UnixListener::from(s))
    }
}

#[cfg(all(unix, not(target_os = "freebsd")))]
fn bind_socket(dir: &Path, name: &str) -> std::io::Result<std::os::unix::net::UnixListener> {
    std::os::unix::net::UnixListener::bind(dir.join(name))
}

#[cfg(not(unix))]
fn relay_ssh_agent(
    _: &Path,
    _: &str,
    _: &Path,
    line: usize,
) -> Result<tokio::task::JoinHandle<()>, Error> {
    Err(Error::Build(format!(
        "line {line}: ssh mounts need a FreeBSD host"
    )))
}

/// Whether `filter` keeps anything below `dir`, a directory it leaves out
/// itself.
fn holds_kept(dir: &Path, filter: &dyn Fn(&Path) -> Keep) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|e| {
        let p = e.path();
        match filter(&p) {
            Keep::Yes => true,
            Keep::Below => {
                std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) && holds_kept(&p, filter)
            }
            Keep::No => false,
        }
    })
}

/// Whether `ignore` leaves out anything below `dir`, a context directory.
fn any_ignored(context_dir: &Path, dir: &Path, ignore: &IgnoreMatcher) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|e| {
        let p = e.path();
        let rel = p
            .strip_prefix(context_dir)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");
        ignore.is_ignored(&rel)
            || (!p.is_symlink() && p.is_dir() && any_ignored(context_dir, &p, ignore))
    })
}

/// A digest of what a step sees of a mounted file or directory tree: the
/// contents, and the mode and owner of each file, the mounted one too.
fn content_digest(path: &Path) -> Result<String, Error> {
    let meta = std::fs::metadata(path)?;
    // The mounted file or directory itself.
    let mut text = owner_mode(&meta);
    if !meta.is_dir() {
        let mut bytes = std::fs::read(path)?;
        bytes.extend_from_slice(format!("\0{text}").as_bytes());
        return Ok(sha256(&bytes));
    }
    text.push('\n');
    let state = TreeState::capture_tree(path)?;
    for (p, e) in &state.entries {
        text.push_str(&format!(
            "{p}\0{:?}\0{:o}\0{}:{}\0{:x}\0{}",
            e.kind, e.mode, e.uid, e.gid, e.flags, e.digest_or_link
        ));
        // Which files are one, by hard links.
        if let Some(first) = state.link_of(p) {
            text.push_str(&format!("\0= {first}"));
        }
        text.push('\n');
    }
    Ok(sha256(text.as_bytes()))
}

/// A file's mode and owner, as `content_digest` keys them.
fn owner_mode(meta: &std::fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        format!("{:o} {}:{}", meta.mode() & 0o7777, meta.uid(), meta.gid())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        String::new()
    }
}

#[cfg(unix)]
fn set_owner_mode(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_mode(_: &Path, _: u32, _: u32, _: u32) -> Result<(), Error> {
    Ok(())
}

async fn commit_step_diff(
    env: BuildEnv<'_>,
    stage: &mut BuiltStage,
    before: &TreeState,
    step_no: usize,
    created_by: &str,
) -> Result<Option<CachedLayer>, Error> {
    let BuildEnv {
        store,
        pin,
        tmp_dir,
        ..
    } = env;
    let compression = env.opts.compression;
    let tar_out = tmp_dir.join(format!("step-{}-{step_no}.tar", stage.layers.len()));
    let gz_out = tmp_dir.join(format!("step-{}-{step_no}.tar.gz", stage.layers.len()));
    let (diff, after) =
        layer::create_diff_layer(before, &stage.root, &tar_out, &gz_out, compression)?;
    stage.tree = Some(after);
    match diff {
        Some(art) => {
            let parent_hex = stage.layers.last().cloned();
            stage.config.rootfs.diff_ids.push(art.diff_id.clone());
            let chains = chain_ids(&stage.config.rootfs.diff_ids);
            let chain_hex = hex_of(chains.last().unwrap())?.to_owned();
            let mut desc = store
                .commit_built_layer(
                    pin,
                    parent_hex.as_deref(),
                    &chain_hex,
                    &tar_out,
                    &gz_out,
                    &art,
                )
                .await?;
            desc.media_type = compression.media_type().to_owned();
            let _ = std::fs::remove_file(&tar_out);
            let _ = std::fs::remove_file(&gz_out);
            stage.layers.push(chain_hex.clone());
            stage.descriptors.push(desc.clone());
            record_history(&mut stage.config, created_by, false);
            Ok(Some(CachedLayer {
                chain: chain_hex,
                diff_id: art.diff_id,
                descriptor: desc,
            }))
        }
        None => {
            record_history(&mut stage.config, created_by, true);
            Ok(None)
        }
    }
}

/// A stage's first cache key. zstd layers are told apart from gzip ones,
/// whose keys stay as they were before there was a choice.
fn root_key(opts: &BuildOptions, parts: &[&str]) -> String {
    let key = next_key("", parts);
    match opts.compression {
        layer::Compression::Gzip => key,
        layer::Compression::Zstd => next_key(&key, &["zstd"]),
    }
}

/// Extends a stage's cache key with one step's inputs.
fn next_key(prev: &str, parts: &[&str]) -> String {
    let mut buf = prev.to_owned();
    for p in parts {
        buf.push('\0');
        buf.push_str(p);
    }
    sha256(buf.as_bytes())["sha256:".len()..].to_owned()
}

/// The key after a `COPY` or `ADD`, which always runs: the layer it left
/// names the copied content exactly.
fn copy_key(stage: &BuiltStage, raw: &str) -> String {
    let top = stage.layers.last().map_or("", String::as_str);
    next_key(&stage.cache_key, &["copy", raw, top])
}

/// Applies a cached step's layer to the stage. Returns false, changing
/// nothing, if the layer does not follow the stage's current layers.
fn apply_cached(
    store: &Store,
    stage: &mut BuiltStage,
    tmp_dir: &Path,
    layer: Option<&CachedLayer>,
) -> Result<bool, Error> {
    let Some(l) = layer else {
        return Ok(true);
    };
    let mut diff_ids = stage.config.rootfs.diff_ids.clone();
    diff_ids.push(l.diff_id.clone());
    let chains = chain_ids(&diff_ids);
    if chains.last().and_then(|c| hex_of(c).ok()) != Some(l.chain.as_str()) {
        return Ok(false);
    }
    let tar = tmp_dir.join("cached.tar");
    let applied = layer::decompress(&store.blob_path(&l.descriptor.digest)?, &l.diff_id, &tar)
        .and_then(|()| layer::apply(&tar, &stage.root));
    let _ = std::fs::remove_file(&tar);
    applied?;
    stage.config.rootfs.diff_ids = diff_ids;
    stage.layers.push(l.chain.clone());
    stage.descriptors.push(l.descriptor.clone());
    Ok(true)
}

/// Files a `COPY` or `ADD` takes from outside the context and stages:
/// here-documents and, for `ADD`, downloads. Removed on drop.
struct CopyExtras {
    _dir: Option<tempfile::TempDir>,
    files: Vec<PathBuf>,
}

impl CopyExtras {
    async fn prepare(
        spec: &CopySpec,
        vars: &BTreeMap<String, String>,
        tmp_dir: &Path,
        is_add: bool,
        line: usize,
    ) -> Result<Self, Error> {
        let urls: Vec<String> = spec
            .sources
            .iter()
            .map(|s| expand_word(s, vars))
            .filter(|s| is_add && is_url(s))
            .collect();
        if spec.checksum.is_some()
            && (urls.len() != 1 || spec.sources.len() != 1 || !spec.heredocs.is_empty())
        {
            return Err(Error::Build(format!(
                "line {line}: ADD --checksum needs exactly one http(s) source"
            )));
        }
        if urls.is_empty() && spec.heredocs.is_empty() {
            return Ok(Self {
                _dir: None,
                files: Vec::new(),
            });
        }
        let dir = tempfile::Builder::new()
            .prefix("copy")
            .tempdir_in(tmp_dir)?;
        let mut files = Vec::new();
        for (i, h) in spec.heredocs.iter().enumerate() {
            let name = Path::new(&h.name).file_name().ok_or_else(|| {
                Error::Build(format!("line {line}: here-document name {:?}", h.name))
            })?;
            let sub = dir.path().join(format!("h{i}"));
            std::fs::create_dir(&sub)?;
            let path = sub.join(name);
            let text = if h.expand {
                expand_vars(&h.body, vars)
            } else {
                h.body.clone()
            };
            std::fs::write(&path, text)?;
            set_mode(&path, 0o644)?;
            files.push(path);
        }
        for (i, url) in urls.iter().enumerate() {
            let name = url
                .split(['?', '#'])
                .next()
                .and_then(|u| u.rsplit('/').next())
                .filter(|n| !n.is_empty() && *n != "." && *n != "..")
                .unwrap_or("download");
            let sub = dir.path().join(format!("u{i}"));
            std::fs::create_dir(&sub)?;
            let path = sub.join(name);
            let sum = spec
                .checksum
                .as_ref()
                .map(|c| containerfile::checksum(&expand_word(c, vars)))
                .transpose()
                .map_err(|e| Error::Build(format!("line {line}: {e}")))?;
            download(url, &path, sum.as_deref(), line).await?;
            set_mode(&path, 0o600)?;
            files.push(path);
        }
        Ok(Self {
            _dir: Some(dir),
            files,
        })
    }
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Fetches `url` to `path`, checking its digest if `checksum` is given.
async fn download(
    url: &str,
    path: &Path,
    checksum: Option<&str>,
    line: usize,
) -> Result<(), Error> {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    let fail = |e: String| Error::Build(format!("line {line}: ADD {url}: {e}"));
    let mut resp = crate::http_client()
        .build()
        .map_err(|e| fail(e.to_string()))?
        .get(url)
        .send()
        .await
        .map_err(|e| fail(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(fail(format!("HTTP {}", resp.status())));
    }
    let mut file = std::fs::File::create(path)?;
    let mut hasher = Sha256::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| fail(e.to_string()))? {
        hasher.update(&chunk);
        file.write_all(&chunk)?;
    }
    let got = format!("sha256:{:x}", hasher.finalize());
    if let Some(want) = checksum
        && want != got
    {
        return Err(fail(format!("checksum is {got}, expected {want}")));
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) -> Result<(), Error> {
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_copy(
    context_dir: &Path,
    ignore: &IgnoreMatcher,
    completed_stages: &[BuiltStage],
    // The image `--from` names, extracted, when it names no stage.
    from_image: Option<&Path>,
    stage: &mut BuiltStage,
    vars: &BTreeMap<String, String>,
    spec: &CopySpec,
    is_add: bool,
    extras: &[PathBuf],
    tmp_dir: &Path,
    line_no: usize,
) -> Result<(), Error> {
    let (src_root, use_ignore) = match (&spec.from, from_image) {
        (Some(_), Some(root)) => (root, false),
        (Some(from_stage), None) => {
            let st = find_stage(completed_stages, from_stage).ok_or_else(|| {
                Error::Build(format!(
                    "line {line_no}: `COPY --from={from_stage}`: stage not found"
                ))
            })?;
            (st.root.as_path(), false)
        }
        (None, _) => (context_dir, true),
    };
    let exclude = IgnoreMatcher::parse(
        &spec
            .exclude
            .iter()
            .map(|p| expand_word(p, vars))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let ignored = |p: &Path| use_ignore && ignore.is_ignored(&rel_path(p, src_root));
    // `--exclude` is matched below each source, and a source by its name.
    let excluded = |p: &Path, source: &Path| {
        exclude.is_ignored(&if p == source {
            rel_path(p, src_root)
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_owned()
        } else {
            rel_path(p, source)
        })
    };

    let chown_ids = match &spec.chown {
        Some(ch) => {
            let expanded = expand_word(ch, vars);
            let passwd = account_file(&stage.root, "passwd");
            let group = account_file(&stage.root, "group");
            let acc = users::resolve(&expanded, &passwd, &group)
                .map_err(|e| Error::Build(format!("line {line_no}: --chown={expanded}: {e}")))?;
            Some((acc.uid, acc.gid))
        }
        None => None,
    };

    let dest_expanded = expand_word(&spec.destination, vars);
    let dest_in_container = if dest_expanded.starts_with('/') {
        dest_expanded.clone()
    } else {
        let wd = if stage.config.config.working_dir.is_empty() {
            "/"
        } else {
            &stage.config.config.working_dir
        };
        format!("{}/{}", wd.trim_end_matches('/'), dest_expanded)
    };
    let dst_base = resolve_in_root(&stage.root, &dest_in_container, true)?;
    // A stage's or an image's files keep their flags; the context's do not,
    // as Docker keeps nothing of the host's.
    let copier = Copier::new(&stage.root, chown_ids, spec.chmod, spec.from.is_some());
    // Whether a path is copied: left out, a directory may still hold
    // something a `!` pattern takes back.
    let keep = |p: &Path, source: &Path| {
        let ig = ignored(p);
        let ex = excluded(p, source);
        if !ig && !ex {
            Keep::Yes
        } else if (!ig || ignore.may_reinclude(&rel_path(p, src_root)))
            && (!ex || exclude.may_reinclude(&rel_path(p, source)))
        {
            Keep::Below
        } else {
            Keep::No
        }
    };

    // Each match, with the path `--parents` keeps for it.
    let mut matched_sources: Vec<(PathBuf, PathBuf)> = Vec::new();
    for raw_src in &spec.sources {
        let src_pat = expand_word(raw_src, vars);
        if is_add && is_url(&src_pat) {
            continue;
        }
        // With `--parents`, `a/./b` keeps only the path below `a`.
        let (pivot, pattern) = match src_pat.split_once("/./") {
            Some((pivot, rest)) if spec.parents => (pivot.to_owned(), format!("{pivot}/{rest}")),
            _ => (String::new(), src_pat.clone()),
        };
        let pivot_root = resolve_in_root(src_root, pivot.trim_start_matches('/'), true)
            .map_err(|e| Error::Build(format!("line {line_no}: {e}")))?;
        // A source .containerignore leaves out is not in the context, but
        // for what a `!` pattern takes back from a directory.
        // As in Docker, such a directory is there only with something in
        // it.
        let in_context = |p: &Path| {
            if !ignored(p) {
                Keep::Yes
            } else if ignore.may_reinclude(&rel_path(p, src_root)) {
                Keep::Below
            } else {
                Keep::No
            }
        };
        let matches: Vec<PathBuf> = resolve_source_paths(src_root, &pattern, line_no)?
            .into_iter()
            .filter(|m| match in_context(m) {
                Keep::Yes => true,
                Keep::Below => m.is_dir() && holds_kept(m, &in_context),
                Keep::No => false,
            })
            .collect();
        if matches.is_empty() {
            return Err(Error::Build(format!(
                "line {line_no}: source {src_pat:?} not found"
            )));
        }
        for m in matches {
            if excluded(&m, &m) {
                continue;
            }
            let rel = m.strip_prefix(src_root).unwrap_or(&m);
            let kept = m.strip_prefix(&pivot_root).unwrap_or(rel).to_path_buf();
            matched_sources.push((m, kept));
        }
    }

    // As with several sources, many matches go into a directory.
    let dest_is_dir_hint = dest_expanded.ends_with('/')
        || dest_expanded == "."
        || spec.parents
        || spec.sources.len() + spec.heredocs.len() > 1
        || matched_sources.len() + extras.len() > 1;
    let place_file = |src: &Path, dst_base: &Path| -> Result<(), Error> {
        let final_dst = if dest_is_dir_hint || dst_base.is_dir() {
            std::fs::create_dir_all(dst_base)?;
            dst_base.join(
                src.file_name()
                    .ok_or_else(|| Error::Build(format!("line {line_no}: invalid source")))?,
            )
        } else {
            if let Some(parent) = dst_base.parent() {
                std::fs::create_dir_all(parent)?;
            }
            dst_base.to_path_buf()
        };
        copier.entry(src, &final_dst)
    };

    for (src_path, kept) in matched_sources {
        let meta = std::fs::symlink_metadata(&src_path)?;
        if meta.is_dir() {
            let dst = if spec.parents {
                resolve_below(&stage.root, &dst_base.join(&kept), true)?
            } else {
                dst_base.clone()
            };
            let filter = |p: &Path| keep(p, &src_path);
            if ignored(&src_path) {
                copier.below(&src_path, &dst, &filter)?;
            } else {
                copier.dir(&src_path, &dst, &filter)?;
            }
        } else if let Some(archive) = is_add
            // Read, not copied: a link to it is followed inside the root.
            .then(|| resolve_below(src_root, &src_path, true).ok())
            .flatten()
            .filter(|a| std::fs::symlink_metadata(a).is_ok_and(|m| m.is_file()) && is_archive(a))
        {
            // tar finds the compression itself; the archive has no diff_id
            // to check.
            std::fs::create_dir_all(&dst_base)?;
            if chown_ids.is_none() && spec.chmod.is_none() {
                unpack_archive(&archive, &dst_base)?;
            } else {
                // Unpacked aside, then copied in with the owner and mode
                // asked for, and the archive's links and flags.
                let aside = tempfile::Builder::new().prefix("add").tempdir_in(tmp_dir)?;
                unpack_archive(&archive, aside.path())?;
                let mut unpacked = Copier::new(&stage.root, chown_ids, spec.chmod, true);
                unpacked.over_dirs = true;
                let copied = (|| {
                    for entry in std::fs::read_dir(aside.path())? {
                        let path = entry?.path();
                        let name = path.file_name().unwrap_or_default();
                        if std::fs::symlink_metadata(&path)?.is_dir() {
                            let target = resolve_below(&stage.root, &dst_base.join(name), true)?;
                            unpacked.dir(&path, &target, &|_| Keep::Yes)?;
                        } else {
                            unpacked.entry(&path, &dst_base.join(name))?;
                        }
                    }
                    unpacked.finish()
                })();
                // Its files may carry flags that refuse a plain removal.
                let _ = layer::remove_tree(aside.path());
                copied?;
            }
        } else if spec.parents {
            let parent = kept.parent().map_or(dst_base.clone(), |p| dst_base.join(p));
            let parent = resolve_below(&stage.root, &parent, true)?;
            std::fs::create_dir_all(&parent)?;
            let name = kept
                .file_name()
                .ok_or_else(|| Error::Build(format!("line {line_no}: invalid source")))?;
            copier.entry(&src_path, &parent.join(name))?;
        } else {
            place_file(&src_path, &dst_base)?;
        }
    }
    for extra in extras {
        place_file(extra, &dst_base)?;
    }
    copier.finish()
}

/// Whether a copy takes a path, or leaves it out with what is below it, or
/// leaves out only the path (a directory) itself.
#[derive(Clone, Copy)]
enum Keep {
    Yes,
    No,
    Below,
}

/// `p` below `base`, with `/` between its components.
fn rel_path(p: &Path, base: &Path) -> String {
    p.strip_prefix(base)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Where a `WORKDIR` of `path` goes from `current`: as in Docker, a path
/// relative to `current`, with `.` and `..` resolved by name (`..` of `/`
/// is `/`).
fn workdir_path(current: &str, path: &str) -> String {
    let joined = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("{current}/{path}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    format!("/{}", parts.join("/"))
}

/// The shell of a `SHELL`, in this image or one it is built on: empty for
/// `/bin/sh -c`.
fn shell_of(cfg: &ImageConfig) -> Vec<String> {
    cfg.config
        .extra
        .get("Shell")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

/// Whether `ADD` unpacks the local file `p`: by its contents, whatever its
/// name, as BuildKit does. A tar, as it is or compressed with gzip, bzip2,
/// xz or zstd, whose first header is one.
fn is_archive(p: &Path) -> bool {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(p) else {
        return false;
    };
    let mut file = std::io::BufReader::new(file);
    let Ok(magic) = std::io::BufRead::fill_buf(&mut file).map(<[u8]>::to_vec) else {
        return false;
    };
    let mut header = [0u8; 512];
    let read = |r: &mut dyn Read, h: &mut [u8; 512]| r.read_exact(h).is_ok();
    if magic.starts_with(&[0x1f, 0x8b]) {
        read(&mut flate2::read::MultiGzDecoder::new(file), &mut header) && is_tar_header(&header)
    } else if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        zstd::stream::read::Decoder::new(file)
            .is_ok_and(|mut d| read(&mut d, &mut header) && is_tar_header(&header))
    } else if magic.starts_with(b"BZh") || magic.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        // Left to bsdtar, which unpacks it: an archive it lists, but a tar.
        std::process::Command::new("tar")
            .arg("-tvf")
            .arg(p)
            .output()
            .is_ok_and(|o| o.status.success() && !o.stdout.is_empty())
    } else {
        read(&mut file, &mut header) && is_tar_header(&header)
    }
}

/// Whether `h` is a tar header: not the zeros that end an archive, with
/// its checksum, as Go's archive/tar takes it (bytes summed unsigned or
/// signed, the checksum's own as spaces).
fn is_tar_header(h: &[u8; 512]) -> bool {
    if h.iter().all(|&b| b == 0) {
        return false;
    }
    let field = std::str::from_utf8(&h[148..156])
        .ok()
        .map(|s| s.trim_matches(|c: char| c == ' ' || c == '\0'))
        .and_then(|s| u64::from_str_radix(s, 8).ok());
    let Some(sum) = field else {
        return false;
    };
    let (mut unsigned, mut signed) = (0u64, 0i64);
    for (i, &b) in h.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += u64::from(b);
        signed += i64::from(b as i8);
    }
    sum == unsigned || i64::try_from(sum).is_ok_and(|s| s == signed)
}

/// The paths a source names, with wildcards allowed in any component.
fn resolve_source_paths(
    src_root: &Path,
    pattern: &str,
    line_no: usize,
) -> Result<Vec<PathBuf>, Error> {
    let trimmed = pattern.trim_start_matches('/');
    safe_join_in_root(src_root, trimmed)
        .map_err(|e| Error::Build(format!("line {line_no}: {e}")))?;
    let mut found = vec![src_root.to_path_buf()];
    let comps: Vec<&str> = trimmed
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    for (i, comp) in comps.iter().enumerate() {
        // A link on the way is followed inside `src_root`; one at the end is
        // copied as a link.
        let last = i + 1 == comps.len();
        let mut next = Vec::new();
        for dir in &found {
            if comp.contains(['*', '?', '[']) {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    continue;
                };
                let mut names: Vec<PathBuf> = entries
                    .filter_map(Result::ok)
                    .filter(|e| e.file_name().to_str().is_some_and(|n| glob_match(comp, n)))
                    .map(|e| e.path())
                    .collect();
                names.sort();
                next.extend(names);
            } else {
                let p = dir.join(comp);
                if std::fs::symlink_metadata(&p).is_ok() {
                    next.push(p);
                }
            }
        }
        if !last {
            next = next
                .iter()
                .map(|p| resolve_below(src_root, p, true))
                .collect::<Result<_, _>>()?;
        }
        found = next;
    }
    Ok(found)
}

fn safe_join_in_root(root: &Path, rel: &str) -> Result<PathBuf, Error> {
    let mut out = root.to_path_buf();
    for c in Path::new(rel).components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(s) => out.push(s),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(Error::Build(format!(
                    "path {rel:?} escapes the root directory"
                )));
            }
        }
    }
    Ok(out)
}

/// `rel`, a path in a root filesystem, under `root`, with the links on its
/// way followed as they would be in a jail on `root`: an absolute link
/// starts again from `root`, and `..` stops there. A build runs as root on
/// the host, so a link in an image or the context must not take what is
/// read or written there outside its root. A link at the end is followed
/// only if `follow_last`; what does not exist yet is kept as named.
pub(crate) fn resolve_in_root(root: &Path, rel: &str, follow_last: bool) -> Result<PathBuf, Error> {
    safe_join_in_root(root, rel)?;
    resolve_in_jail(root, rel, follow_last)
}

/// The image's `/etc/{name}` (`passwd`, `group`), read as a jail on `root`
/// reads it: a link to it is followed within `root`, never to the host's.
/// One that is not there reads as empty.
pub(crate) fn account_file(root: &Path, name: &str) -> String {
    resolve_in_jail(root, &format!("/etc/{name}"), true)
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default()
}

/// [`resolve_in_root`], with `..` in `path` allowed, as a jail on `root`
/// takes it: a command's path in an image, not a path a Containerfile
/// names.
pub(crate) fn resolve_in_jail(
    root: &Path,
    path: &str,
    follow_last: bool,
) -> Result<PathBuf, Error> {
    let rel = path;
    // What is left to walk, last first.
    let mut todo: Vec<std::ffi::OsString> = Path::new(rel)
        .components()
        .rev()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_owned()),
            Component::ParentDir => Some("..".into()),
            _ => None,
        })
        .collect();
    let mut done = root.to_path_buf();
    let mut depth = 0usize;
    let mut links = 0;
    while let Some(name) = todo.pop() {
        if name == ".." {
            if depth > 0 {
                done.pop();
                depth -= 1;
            }
            continue;
        }
        let next = done.join(&name);
        let is_link = std::fs::symlink_metadata(&next).is_ok_and(|m| m.file_type().is_symlink());
        if is_link && (follow_last || !todo.is_empty()) {
            links += 1;
            if links > 40 {
                return Err(Error::Build(format!("path {rel:?}: too many links")));
            }
            let link = std::fs::read_link(&next)?;
            if link.has_root() {
                done = root.to_path_buf();
                depth = 0;
            }
            for c in link.components().rev() {
                match c {
                    Component::Normal(s) => todo.push(s.to_owned()),
                    Component::ParentDir => todo.push("..".into()),
                    _ => {}
                }
            }
        } else {
            done = next;
            depth += 1;
        }
    }
    Ok(done)
}

/// Unpacks a tar archive `ADD` names into `dst`, with what a layer keeps
/// (numeric owners, modes, file flags) but every name in it: a `.wh.` file
/// is an ordinary one here, not a whiteout.
fn unpack_archive(archive: &Path, dst: &Path) -> Result<(), Error> {
    let mut cmd = std::process::Command::new("tar");
    cmd.arg("-x");
    if cfg!(target_os = "freebsd") {
        cmd.args(["-p", "--numeric-owner", "--fflags", "--xattrs"]);
    }
    let out = cmd.arg("-f").arg(archive).arg("-C").arg(dst).output()?;
    if !out.status.success() {
        return Err(Error::Build(format!(
            "unpacking {}: {}",
            archive.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// `path`, below `root`, with its links resolved by [`resolve_in_root`].
fn resolve_below(root: &Path, path: &Path, follow_last: bool) -> Result<PathBuf, Error> {
    let rel = path.strip_prefix(root).unwrap_or(path);
    resolve_in_root(root, &rel.to_string_lossy().replace('\\', "/"), follow_last)
}

/// Copies files for one `COPY`: owners and modes as it asks, the names
/// of a hard-linked file linked again, and (from a stage or an image) the
/// source's owners and its file flags, set at the end, since they may
/// refuse what follows.
struct Copier {
    /// The root filesystem copied into, which its links stay inside.
    root: PathBuf,
    chown: Option<(u32, u32)>,
    chmod: Option<u32>,
    keep_flags: bool,
    /// Whether a file may take the place of a directory, as unpacking an
    /// archive lets it; a copy may not, as in BuildKit.
    over_dirs: bool,
    /// The first copy of each hard-linked source file, by device and inode.
    linked: std::cell::RefCell<HashMap<(u64, u64), PathBuf>>,
    /// Flags to set when all is copied, in the order to set them.
    flags: std::cell::RefCell<Vec<(PathBuf, u32)>>,
}

impl Copier {
    fn new(root: &Path, chown: Option<(u32, u32)>, chmod: Option<u32>, keep_flags: bool) -> Self {
        Copier {
            root: root.to_path_buf(),
            chown,
            chmod,
            keep_flags,
            over_dirs: false,
            linked: Default::default(),
            flags: Default::default(),
        }
    }

    /// Makes the directory `dst` if it is not there, and returns the
    /// directories made, `dst` first, then its parents. As in BuildKit, a
    /// directory is not copied over a file.
    fn make_dir(&self, dst: &Path) -> Result<Vec<PathBuf>, Error> {
        match std::fs::symlink_metadata(dst) {
            Ok(m) if m.is_dir() => Ok(Vec::new()),
            Ok(_) => Err(Error::Build(format!(
                "cannot copy to non-directory: /{}",
                rel_path(dst, &self.root)
            ))),
            Err(_) => {
                let mut made = Vec::new();
                let mut d = dst;
                while std::fs::symlink_metadata(d).is_err() {
                    made.push(d.to_path_buf());
                    let Some(parent) = d.parent() else { break };
                    d = parent;
                }
                std::fs::create_dir_all(dst)?;
                Ok(made)
            }
        }
    }

    /// Gives `dst`, a directory the copy made for `src`, `src`'s mode, so
    /// that a 0700 one stays closed, and from a stage or an image its
    /// owner, unless `--chown` and `--chmod` say otherwise.
    fn made_from(&self, src: &Path, dst: &Path) -> Result<(), Error> {
        let meta = std::fs::metadata(src)?;
        apply_perms(
            dst,
            self.chown.or(self.source_owner(&meta)),
            self.chmod.or(file_mode(&meta)),
        )
    }

    /// Copies the tree `src_dir` to `dst_dir`, leaving out what `skip`
    /// names (by path below `root`).
    fn dir(
        &self,
        src_dir: &Path,
        dst_dir: &Path,
        filter: &dyn Fn(&Path) -> Keep,
    ) -> Result<(), Error> {
        // One already there keeps its own mode and owner.
        if self.make_dir(dst_dir)?.is_empty() {
            apply_perms(dst_dir, self.chown, self.chmod)?;
        } else {
            self.made_from(src_dir, dst_dir)?;
        }
        for entry in std::fs::read_dir(src_dir)? {
            let entry = entry?;
            let path = entry.path();
            let target = dst_dir.join(entry.file_name());
            let is_dir = std::fs::symlink_metadata(&path)?.is_dir();
            match filter(&path) {
                Keep::No => {}
                Keep::Below if is_dir => {
                    self.below(&path, &resolve_below(&self.root, &target, true)?, filter)?;
                }
                Keep::Below => {}
                Keep::Yes if is_dir => {
                    // A directory already there may be a link, as `/home` is.
                    let target = resolve_below(&self.root, &target, true)?;
                    self.dir(&path, &target, filter)?;
                }
                Keep::Yes => self.entry(&path, &target)?,
            }
        }
        // After its contents: a flag such as schg refuses them.
        self.keep_flags_of(src_dir, dst_dir)
    }

    /// Copies what `filter` keeps below `src_dir`, a directory left out
    /// itself: `dst_dir` is made only for something in it.
    fn below(
        &self,
        src_dir: &Path,
        dst_dir: &Path,
        filter: &dyn Fn(&Path) -> Keep,
    ) -> Result<(), Error> {
        self.below_at(src_dir, dst_dir, filter, 0)
    }

    /// [`Self::below`], `depth` directories down from where it began: so
    /// many of `dst_dir`'s parents, if it makes them, are made for the
    /// source directories above `src_dir`.
    fn below_at(
        &self,
        src_dir: &Path,
        dst_dir: &Path,
        filter: &dyn Fn(&Path) -> Keep,
        depth: usize,
    ) -> Result<(), Error> {
        for entry in std::fs::read_dir(src_dir)? {
            let entry = entry?;
            let path = entry.path();
            let is_dir = std::fs::symlink_metadata(&path)?.is_dir();
            let keep = filter(&path);
            if matches!(keep, Keep::No) || (matches!(keep, Keep::Below) && !is_dir) {
                continue;
            }
            let target = resolve_below(&self.root, &dst_dir.join(entry.file_name()), true)?;
            match keep {
                Keep::Below => self.below_at(&path, &target, filter, depth + 1)?,
                _ => {
                    let made = self.make_dir(dst_dir)?;
                    for (d, src) in made.iter().zip(src_dir.ancestors()).take(depth + 1) {
                        self.made_from(src, d)?;
                    }
                    if is_dir {
                        self.dir(&path, &target, filter)?;
                    } else {
                        self.entry(&path, &target)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Copies the file or link `src` to `dst`, replacing what is there.
    fn entry(&self, src: &Path, dst: &Path) -> Result<(), Error> {
        let meta = std::fs::symlink_metadata(src)?;
        let key = layer::inode(&meta).filter(|_| !meta.file_type().is_symlink());
        if let Some(key) = key
            && self
                .linked
                .borrow()
                .get(&key)
                .is_some_and(|first| first == dst)
        {
            // Copied there already, by another name for the same file.
            return Ok(());
        }
        if let Ok(there) = std::fs::symlink_metadata(dst) {
            if there.is_dir() && !self.over_dirs {
                return Err(Error::Build(format!(
                    "cannot replace directory /{} with a file",
                    rel_path(dst, &self.root)
                )));
            }
            layer::remove_tree(dst)?;
            // What was there is no longer a copy to link to.
            self.linked.borrow_mut().retain(|_, p| !p.starts_with(dst));
        }
        if meta.file_type().is_symlink() {
            #[cfg(unix)]
            {
                let link = std::fs::read_link(src)?;
                std::os::unix::fs::symlink(link, dst)?;
            }
            #[cfg(windows)]
            let _ = std::fs::copy(src, dst);
        } else if layer::is_fifo(&meta) {
            // Made again: reading one would wait for a writer.
            make_fifo(dst)?;
        } else {
            if let Some(key) = key {
                let first = self.linked.borrow().get(&key).cloned();
                if let Some(first) = first {
                    // The first copy has the owner, mode and flags.
                    std::fs::hard_link(first, dst)?;
                    return Ok(());
                }
                self.linked.borrow_mut().insert(key, dst.to_path_buf());
            }
            std::fs::copy(src, dst)?;
        }
        // The source's mode is set again after its owner, which may clear
        // setuid and setgid bits; a link has none.
        let mode = self.chmod.or(file_mode(&meta));
        apply_perms(dst, self.chown.or(self.source_owner(&meta)), mode)?;
        self.keep_flags_of(src, dst)
    }

    /// The owner of a file copied from a stage or an image; one from the
    /// context is root's, as in Docker.
    fn source_owner(&self, meta: &std::fs::Metadata) -> Option<(u32, u32)> {
        #[cfg(unix)]
        if self.keep_flags {
            use std::os::unix::fs::MetadataExt;
            return Some((meta.uid(), meta.gid()));
        }
        let _ = meta;
        None
    }

    fn keep_flags_of(&self, src: &Path, dst: &Path) -> Result<(), Error> {
        if self.keep_flags {
            let flags = layer::file_flags(&std::fs::symlink_metadata(src)?);
            if flags != 0 {
                self.flags.borrow_mut().push((dst.to_path_buf(), flags));
            }
        }
        Ok(())
    }

    /// Sets the flags kept: files before the directories holding them.
    fn finish(&self) -> Result<(), Error> {
        for (path, flags) in self.flags.borrow().iter() {
            layer::set_flags(path, *flags)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn make_fifo(path: &Path) -> Result<(), Error> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::Build(format!("{}: NUL in path", path.display())))?;
    // SAFETY: `c` is a valid NUL-terminated path.
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_fifo(path: &Path) -> Result<(), Error> {
    Err(Error::Build(format!(
        "{}: named pipes need a FreeBSD host",
        path.display()
    )))
}

/// The permission bits of `meta`, on a system that has them.
fn file_mode(meta: &std::fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(meta.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

fn apply_perms(
    path: &Path,
    chown_ids: Option<(u32, u32)>,
    chmod: Option<u32>,
) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        // The owner first: a chown may clear setuid and setgid bits.
        if let Some((uid, gid)) = chown_ids {
            let c = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| Error::Build(format!("{}: NUL in path", path.display())))?;
            // Only root can give a file away: a build run by another user
            // keeps the files its own, as it did before.
            if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EPERM) || unsafe { libc::geteuid() } == 0 {
                    return Err(Error::Build(format!(
                        "chown {uid}:{gid} {}: {e}",
                        path.display()
                    )));
                }
            }
        }
        if let Some(mode) = chmod
            && let Ok(meta) = std::fs::symlink_metadata(path)
            && !meta.file_type().is_symlink()
        {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }
    }
    let _ = (path, chown_ids, chmod);
    Ok(())
}

/// Writes `data` to a new file at `path`, readable only by its owner from
/// the start.
fn write_private(path: &Path, data: &[u8]) -> Result<(), Error> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    std::io::Write::write_all(&mut o.open(path)?, data)?;
    Ok(())
}

fn set_env(env: &mut Vec<String>, key: &str, value: &str) {
    let prefix = format!("{key}=");
    if let Some(slot) = env.iter_mut().find(|e| e.starts_with(&prefix)) {
        *slot = format!("{key}={value}");
    } else {
        env.push(format!("{key}={value}"));
    }
}

fn record_history(cfg: &mut ImageConfig, created_by: &str, empty_layer: bool) {
    cfg.history.push(History {
        created: String::new(),
        created_by: created_by.to_owned(),
        empty_layer,
    });
}

async fn build_with_buildah(
    store: &Arc<Store>,
    cf_path: &Path,
    opts: &BuildOptions,
) -> Result<Image, Error> {
    // Options that only mean something to the native builder: say so rather
    // than build without them.
    let unsupported = [
        (!opts.jail_params.is_empty(), "--param and --sysv"),
        (!opts.limits.is_empty(), "--memory, --cpus and --pids-limit"),
        (opts.cpuset.is_some(), "--cpuset-cpus"),
        (!opts.cache_from.is_empty(), "--cache-from"),
        (opts.cache_to.is_some(), "--cache-to"),
    ];
    if let Some((_, flag)) = unsupported.iter().find(|(set, _)| *set) {
        return Err(Error::Build(format!(
            "{flag}: not supported with --backend buildah"
        )));
    }
    let tag_ref = Reference::parse_local_tag(&opts.tag)?.to_string();
    let tmp = tempfile::Builder::new()
        .prefix("buildah-export")
        .tempdir_in(store.dir().join("tmp"))?;
    let mut cmd = tokio::process::Command::new("buildah");
    cmd.args(["bud", "--network", "host", "-f"])
        .arg(cf_path)
        .arg("-t")
        .arg(&tag_ref);
    for (k, v) in &opts.build_args {
        cmd.arg("--build-arg").arg(format!("{k}={v}"));
    }
    if let Some(t) = &opts.target {
        cmd.arg("--target").arg(t);
    }
    if opts.no_cache {
        cmd.arg("--no-cache");
    }
    if opts.squash {
        cmd.arg("--squash");
    }
    for (k, v) in &opts.labels {
        cmd.arg("--label").arg(format!("{k}={v}"));
    }
    for (k, v) in &opts.annotations {
        cmd.arg("--annotation").arg(format!("{k}={v}"));
    }
    if let Some(t) = opts.timestamp {
        cmd.arg("--timestamp").arg(t.to_string());
    }
    if let Some(c) = &opts.creds.creds {
        cmd.arg("--creds").arg(c);
    }
    if let Some(a) = &opts.creds.authfile {
        cmd.arg("--authfile").arg(a);
    }
    // buildah takes secrets from files: they are written, readable only by
    // their owner, below the export directory removed after the build.
    let secrets_dir = tmp.path().join("secrets");
    for (i, (id, data)) in opts.secrets.iter().enumerate() {
        std::fs::create_dir_all(&secrets_dir)?;
        let path = secrets_dir.join(i.to_string());
        write_private(&path, data)?;
        cmd.arg("--secret")
            .arg(format!("id={id},src={}", path.display()));
    }
    for (id, sock) in &opts.ssh {
        cmd.arg("--ssh").arg(format!("{id}={}", sock.display()));
    }
    cmd.arg(&opts.context_dir);
    let status = cmd
        .status()
        .await
        .map_err(|e| Error::Build(format!("running buildah: {e}")))?;
    if !status.success() {
        return Err(Error::Build(format!("buildah bud failed ({status})")));
    }

    let archive = tmp.path().join("image.tar");
    let push_dest = format!("oci-archive:{}:{tag_ref}", archive.display());
    let format = match opts.compression {
        layer::Compression::Gzip => "gzip",
        layer::Compression::Zstd => "zstd",
    };
    let status = tokio::process::Command::new("buildah")
        .args(["push", "--compression-format", format, &tag_ref, &push_dest])
        .status()
        .await
        .map_err(|e| Error::Build(format!("running buildah push: {e}")))?;
    if !status.success() {
        return Err(Error::Build(format!("buildah push failed ({status})")));
    }
    Ok(store.load(&archive, Some(&tag_ref)).await?)
}

#[cfg(test)]
mod tests {
    use super::pull_creds;
    use legion_api::clock::format as rfc3339;

    #[test]
    fn times_are_given_as_image_configs_give_them() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_825_599), "2000-02-29T11:59:59Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn images_are_pulled_with_their_own_registrys_credentials() {
        let tmp = tempfile::tempdir().unwrap();
        let authfile = tmp.path().join("auth.json");
        std::fs::write(
            &authfile,
            r#"{"auths": {
                "ghcr.io": {"username": "gh", "password": "a"},
                "https://index.docker.io/v1/": {"username": "hub", "password": "b"}
            }}"#,
        )
        .unwrap();
        let source = crate::auth::CredsSource {
            creds: None,
            authfile: Some(authfile),
        };
        let user = |name: &str| pull_creds(&source, name).unwrap().map(|c| c.username);
        assert_eq!(user("ghcr.io/me/base:15.1").as_deref(), Some("gh"));
        assert_eq!(user("freebsd/base:15.1").as_deref(), Some("hub"));
        assert_eq!(user("quay.io/me/base:1"), None);
        // `--creds` is for every registry.
        let given = crate::auth::CredsSource {
            creds: Some("me:pw".to_owned()),
            authfile: None,
        };
        let c = pull_creds(&given, "ghcr.io/me/base:15.1").unwrap().unwrap();
        assert_eq!((c.username.as_str(), c.password.as_str()), ("me", "pw"));
    }

    #[cfg(unix)]
    #[test]
    fn a_mounted_files_mode_is_in_its_digest() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("run.sh");
        std::fs::write(&f, "#!/bin/sh\n").unwrap();
        let at = |mode| {
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
            super::content_digest(&f).unwrap()
        };
        assert_ne!(at(0o644), at(0o755));
        assert_eq!(at(0o644), at(0o644));
    }

    #[test]
    fn a_mounted_trees_dev_is_in_its_digest() {
        // A context's `dev` is its own, not a jail's devfs.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("dev")).unwrap();
        let at = |text: &str| {
            std::fs::write(tmp.path().join("dev/input.txt"), text).unwrap();
            super::content_digest(tmp.path()).unwrap()
        };
        assert_ne!(at("one"), at("two"));
    }

    #[cfg(unix)]
    #[test]
    fn hard_links_and_the_roots_mode_are_in_a_trees_digest() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        std::fs::write(&a, "same").unwrap();
        std::fs::write(&b, "same").unwrap();
        let apart = super::content_digest(tmp.path()).unwrap();
        // The same names, contents and modes, but one file.
        std::fs::remove_file(&b).unwrap();
        std::fs::hard_link(&a, &b).unwrap();
        let linked = super::content_digest(tmp.path()).unwrap();
        assert_ne!(apart, linked);
        let mode = std::fs::metadata(tmp.path()).unwrap().permissions().mode();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_ne!(linked, super::content_digest(tmp.path()).unwrap());
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn links_are_followed_inside_the_root() {
        use super::resolve_in_root;
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("usr/home")).unwrap();
        symlink("usr/home", root.join("home")).unwrap();
        symlink("/etc", root.join("abs")).unwrap();
        symlink("../../../..", root.join("usr/up")).unwrap();
        symlink("loop", root.join("loop")).unwrap();
        let at = |p: &str, last| resolve_in_root(&root, p, last).unwrap();
        assert_eq!(at("/home/app", true), root.join("usr/home/app"));
        assert_eq!(at("/abs/rc.conf", true), root.join("etc/rc.conf"));
        assert_eq!(at("usr/up/etc", true), root.join("etc"));
        assert_eq!(at("/abs", false), root.join("abs"));
        assert_eq!(at("/abs", true), root.join("etc"));
        assert!(resolve_in_root(&root, "/loop", true).is_err());
        assert!(resolve_in_root(&root, "../x", true).is_err());
        // A command's path may have `..`; it stops at the root.
        let jail = |p: &str| super::resolve_in_jail(&root, p, true).unwrap();
        assert_eq!(jail("/usr/home/../../etc"), root.join("etc"));
        assert_eq!(jail("../../x"), root.join("x"));
    }

    #[cfg(unix)]
    #[test]
    fn what_a_step_placed_is_removed_through_no_link() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;
        let tmp = tempfile::tempdir().unwrap();
        let (root, host) = (tmp.path().join("root"), tmp.path().join("host"));
        std::fs::create_dir_all(root.join("run/a")).unwrap();
        std::fs::create_dir_all(host.join("z")).unwrap();
        let _in = UnixListener::bind(root.join("run/a/s.sock")).unwrap();
        let _out = UnixListener::bind(host.join("z/s.sock")).unwrap();
        std::fs::write(root.join("run/a/file"), "").unwrap();
        let rm = |rel: &str, dir| super::remove_beneath(&root, std::path::Path::new(rel), dir);
        // A socket goes; anything else in its stead stays.
        rm("run/a/s.sock", false).unwrap();
        assert!(std::fs::symlink_metadata(root.join("run/a/s.sock")).is_err());
        rm("run/a/file", false).unwrap();
        assert!(root.join("run/a/file").exists());
        // A link on the way, absolute, stops it.
        symlink(&host, root.join("run/y")).unwrap();
        assert!(rm("run/y/z/s.sock", false).is_err());
        assert!(rm("run/y/z", true).is_err());
        assert!(std::fs::symlink_metadata(host.join("z/s.sock")).is_ok());
        // A link where a directory was is not one: it stays too.
        assert!(rm("run/y", true).is_err());
        assert!(std::fs::symlink_metadata(root.join("run/y")).is_ok());
        std::fs::remove_file(root.join("run/a/file")).unwrap();
        rm("run/a", true).unwrap();
        assert!(!root.join("run/a").exists());
    }

    #[cfg(unix)]
    #[test]
    fn account_files_are_the_images_through_its_links() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(root.join("usr/local/etc")).unwrap();
        // As the host has its own /etc/passwd, a link to it by an absolute
        // path must find the image's, not the host's.
        std::fs::write(
            root.join("usr/local/etc/passwd"),
            "app:*:1234:1234::/:/bin/sh\n",
        )
        .unwrap();
        symlink("/usr/local/etc/passwd", root.join("etc/passwd")).unwrap();
        // Out of the root by `..`, it stops there.
        symlink("../../../../../../etc/group", root.join("etc/group")).unwrap();
        assert_eq!(
            super::account_file(&root, "passwd"),
            "app:*:1234:1234::/:/bin/sh\n"
        );
        assert_eq!(super::account_file(&root, "group"), "");
        assert_eq!(super::account_file(&tmp.path().join("none"), "passwd"), "");
    }
}
