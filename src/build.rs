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
    self, Containerfile, CopySpec, IgnoreMatcher, Instruction, RunMount, RunOptions, expand_vars,
    glob_match,
};
use crate::layer::{self, TreeState};
use crate::oci::{self, Descriptor, History, ImageConfig};
use crate::registry::{Credentials, sha256};
use crate::runtime::{JailRuntime, Step, StepMount, StepNetwork, target};
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
    shell: Vec<String>,
    /// Identifies the stage's filesystem so far, for the build cache.
    cache_key: String,
    /// The root's state after the last diff, so the next one hashes only
    /// what changed.
    tree: Option<TreeState>,
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
    let mut report = check_containerfile(&cf);

    if opts.backend == BuildBackend::Buildah {
        let image = build_with_buildah(store, &cf_path, opts).await?;
        let tmp_check = tempfile::Builder::new()
            .prefix("check-root")
            .tempdir_in(store.dir().join("tmp"))?;
        if store.prepare_rootfs(&image, tmp_check.path(), None).is_ok() {
            report.merge(check_image(&image.config, Some(tmp_check.path())));
            let _ = store.cleanup_rootfs(tmp_check.path(), None);
        } else {
            report.merge(check_image(&image.config, None));
        }
        if opts.strict_lint && report.has_errors() {
            return Err(Error::Build(
                "Legion compatibility check reported errors".to_owned(),
            ));
        }
        return Ok(BuildResult { image, report });
    }

    let ignore = IgnoreMatcher::from_context_dir(&opts.context_dir);
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

    let mut global_vars = BTreeMap::new();
    for (k, def) in &cf.global_args {
        if let Some(v) = build_args.get(k).or(def.as_ref()) {
            global_vars.insert(k.clone(), v.clone());
        }
    }
    let mut from_vars = predefined;
    from_vars.extend(global_vars.clone());

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
        let mut vars = global_vars.clone();
        let base_ref = expand_vars(&stage_def.base, &from_vars);
        if let Some(p) = &stage_def.platform {
            let p = expand_vars(p, &from_vars);
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
                shell: Vec::new(),
                cache_key: root_key(opts, &["scratch"]),
                tree: None,
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
                shell: prev.shell.clone(),
                cache_key: prev.cache_key.clone(),
                tree: None,
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
                shell: Vec::new(),
                cache_key: root_key(opts, &["from", &base_img.id]),
                tree: None,
            }
        };

        // Seed `vars` with any ENV already present in the base image.
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
        let created = rfc3339(secs);
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
        tmp_dir,
        ..
    } = env;
    let (no_cache, context_dir) = (opts.no_cache, opts.context_dir.as_path());
    match &sp.instruction {
        Instruction::Arg { name, default } => {
            if let Some(val) = cli_build_args.get(name) {
                vars.insert(name.clone(), val.clone());
            } else if let Some(def) = default {
                let expanded = expand_vars(def, vars);
                vars.entry(name.clone()).or_insert(expanded);
            }
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Env(pairs) => {
            for (k, v) in pairs {
                let expanded = expand_vars(v, vars);
                vars.insert(k.clone(), expanded.clone());
                set_env(&mut stage.config.config.env, k, &expanded);
            }
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Label(pairs) => {
            for (k, v) in pairs {
                let expanded = expand_vars(v, vars);
                stage.config.config.labels.insert(k.clone(), expanded);
            }
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Workdir(wd) => {
            let expanded = expand_vars(wd, vars);
            let new_wd = if expanded.starts_with('/') {
                expanded
            } else {
                let base = if stage.config.config.working_dir.is_empty() {
                    "/"
                } else {
                    &stage.config.config.working_dir
                };
                format!("{}/{}", base.trim_end_matches('/'), expanded)
            };
            let _ = target(&stage.root, &new_wd, false)?;
            stage.config.config.working_dir = new_wd;
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::User(u) => {
            stage.config.config.user = expand_vars(u, vars);
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Expose(ports) => {
            for p in ports {
                let expanded = expand_vars(p, vars);
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
                let expanded = expand_vars(v, vars);
                stage
                    .config
                    .config
                    .volumes
                    .insert(expanded, serde_json::json!({}));
            }
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Stopsignal(sig) => {
            stage.config.config.stop_signal = expand_vars(sig, vars);
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Shell(sh) => {
            stage.shell = sh.clone();
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
            stage.config.config.entrypoint = form.to_argv(&stage.shell);
            stage.config.config.cmd.clear();
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Cmd(form) => {
            stage.config.config.cmd = form.to_argv(&stage.shell);
            record_history(&mut stage.config, &sp.raw, true);
        }
        Instruction::Copy(spec) | Instruction::Add(spec) => {
            let is_add = matches!(sp.instruction, Instruction::Add(_));
            let spec = &CopySpec {
                from: spec.from.as_ref().map(|f| expand_vars(f, vars)),
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
            let argv = form.to_argv(&stage.shell);
            let mut run_env = stage.config.config.env.clone();
            for (k, v) in vars.iter() {
                if !run_env
                    .iter()
                    .any(|e| e.split('=').next() == Some(k.as_str()))
                {
                    run_env.push(format!("{k}={v}"));
                }
            }
            let mounts =
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
                    let before = TreeState::capture_from(&stage.root, stage.tree.as_ref())?;
                    let mut id = [0u8; 6];
                    getrandom::fill(&mut id).expect("random bytes");
                    let name: String = std::iter::once("jailer_build_".to_owned())
                        .chain(id.iter().map(|b| format!("{b:02x}")))
                        .collect();
                    let sys = &**store.sys();
                    crate::runtime::limit(sys, &name, &opts.limits)?;
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
                    if !opts.limits.is_empty() {
                        crate::runtime::unlimit(sys, &name);
                    }
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
            stage.cache_key = key;
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
    /// Tasks relaying SSH agent connections, stopped on drop.
    relays: Vec<tokio::task::JoinHandle<()>>,
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
            relays: Vec::new(),
        };
        for (i, m) in opts.mounts.iter().enumerate() {
            let scratch = tmp_dir.join(format!("mount-{step_no}-{i}"));
            match m {
                RunMount::Cache {
                    id,
                    target,
                    read_only,
                    mode,
                    uid,
                    gid,
                } => {
                    let dir = store.dir().join("run-cache").join(next_key("", &[id]));
                    if !dir.exists() {
                        std::fs::create_dir_all(&dir)?;
                        set_owner_mode(&dir, *uid, *gid, *mode)?;
                    }
                    out.key.push_str(&format!("\0cache {id} {target}"));
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
                    let from = from.as_ref().map(|f| expand_vars(f, vars));
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
                    if std::fs::symlink_metadata(&src).is_err()
                        || (from.is_none() && ignore.is_ignored(&rel))
                    {
                        return Err(Error::Build(format!(
                            "line {line}: --mount source {source:?} not found"
                        )));
                    }
                    // As in Docker, the step does not see what .containerignore
                    // leaves out of the context, and `rw` writes are discarded:
                    // both mount a copy.
                    let src =
                        if from.is_none() && src.is_dir() && any_ignored(context_dir, &src, ignore)
                        {
                            let skip = |rel: &str| ignore.is_ignored(rel);
                            let copier = Copier::new(&scratch, None, None, false);
                            copier.dir(context_dir, &src, &scratch, &skip)?;
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
                    std::fs::write(&scratch, value)?;
                    out.temp.push(scratch.clone());
                    set_owner_mode(&scratch, *uid, *gid, *mode)?;
                    out.key.push_str(&format!("\0secret {id} {target}"));
                    out.mounts.push(StepMount::Nullfs {
                        source: scratch,
                        target: target.clone(),
                        read_only: true,
                    });
                }
                RunMount::Tmpfs { target, size } => {
                    out.key.push_str(&format!("\0tmpfs {target}"));
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
                    // nullfs mounts files and directories, not sockets: the
                    // step gets a socket of its own in a directory mounted at
                    // the target's, and jailer relays its connections.
                    let (dir, name) = match target.rsplit_once('/') {
                        Some((d, n)) if !n.is_empty() => (if d.is_empty() { "/" } else { d }, n),
                        _ => {
                            return Err(Error::Build(format!(
                                "line {line}: ssh mount target {target:?}: give a socket path"
                            )));
                        }
                    };
                    std::fs::create_dir_all(&scratch)?;
                    out.temp.push(scratch.clone());
                    let sock = scratch.join(name);
                    out.relays.push(relay_ssh_agent(&sock, agent, line)?);
                    set_owner_mode(&sock, *uid, *gid, *mode)?;
                    out.key.push_str(&format!("\0ssh {id} {target}"));
                    out.env.push(format!("SSH_AUTH_SOCK={target}"));
                    out.mounts.push(StepMount::Nullfs {
                        source: scratch,
                        target: dir.to_owned(),
                        read_only: false,
                    });
                }
            }
        }
        Ok(out)
    }
}

impl Drop for RunMounts {
    fn drop(&mut self) {
        for r in &self.relays {
            r.abort();
        }
        for p in &self.temp {
            let _ = layer::remove_tree(p);
        }
    }
}

/// Listens at `sock` and passes each connection on to the SSH agent at
/// `agent`.
#[cfg(unix)]
fn relay_ssh_agent(
    sock: &Path,
    agent: &Path,
    line: usize,
) -> Result<tokio::task::JoinHandle<()>, Error> {
    let listener = tokio::net::UnixListener::bind(sock)
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

#[cfg(not(unix))]
fn relay_ssh_agent(_: &Path, _: &Path, line: usize) -> Result<tokio::task::JoinHandle<()>, Error> {
    Err(Error::Build(format!(
        "line {line}: ssh mounts need a FreeBSD host"
    )))
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

/// A digest of a file's or directory tree's contents and modes.
fn content_digest(path: &Path) -> Result<String, Error> {
    if !path.is_dir() {
        return Ok(sha256(&std::fs::read(path)?));
    }
    let state = TreeState::capture(path)?;
    let mut text = String::new();
    for (p, e) in &state.entries {
        text.push_str(&format!(
            "{p}\0{:?}\0{:o}\0{}\n",
            e.kind, e.mode, e.digest_or_link
        ));
    }
    Ok(sha256(text.as_bytes()))
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
            .map(|s| expand_vars(s, vars))
            .filter(|s| is_add && is_url(s))
            .collect();
        if spec.checksum.is_some() && (urls.len() != 1 || spec.sources.len() != 1) {
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
            download(url, &path, spec.checksum.as_deref(), line).await?;
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
    let mut resp = reqwest::get(url).await.map_err(|e| fail(e.to_string()))?;
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
            .map(|p| expand_vars(p, vars))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let skip = |rel: &str| (use_ignore && ignore.is_ignored(rel)) || exclude.is_ignored(rel);

    let chown_ids = match &spec.chown {
        Some(ch) => {
            let expanded = expand_vars(ch, vars);
            let passwd = std::fs::read_to_string(stage.root.join("etc/passwd")).unwrap_or_default();
            let group = std::fs::read_to_string(stage.root.join("etc/group")).unwrap_or_default();
            let acc = users::resolve(&expanded, &passwd, &group)
                .map_err(|e| Error::Build(format!("line {line_no}: --chown={expanded}: {e}")))?;
            Some((acc.uid, acc.gid))
        }
        None => None,
    };

    let dest_expanded = expand_vars(&spec.destination, vars);
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
    let dest_is_dir_hint = dest_expanded.ends_with('/')
        || dest_expanded == "."
        || spec.parents
        || spec.sources.len() + spec.heredocs.len() > 1;
    let dst_base = resolve_in_root(&stage.root, &dest_in_container, true)?;
    // A stage's or an image's files keep their flags; the context's do not,
    // as Docker keeps nothing of the host's.
    let copier = Copier::new(&stage.root, chown_ids, spec.chmod, spec.from.is_some());
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

    // Each match, with the path `--parents` keeps for it.
    let mut matched_sources: Vec<(PathBuf, PathBuf)> = Vec::new();
    for raw_src in &spec.sources {
        let src_pat = expand_vars(raw_src, vars);
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
        let matches = resolve_source_paths(src_root, &pattern, line_no)?;
        if matches.is_empty() {
            return Err(Error::Build(format!(
                "line {line_no}: source {src_pat:?} not found"
            )));
        }
        for m in matches {
            let rel = m.strip_prefix(src_root).unwrap_or(&m);
            if skip(&rel.to_string_lossy().replace('\\', "/")) {
                continue;
            }
            let kept = m.strip_prefix(&pivot_root).unwrap_or(rel).to_path_buf();
            matched_sources.push((m, kept));
        }
    }

    for (src_path, kept) in matched_sources {
        let meta = std::fs::symlink_metadata(&src_path)?;
        if meta.is_dir() {
            copier.dir(
                src_root,
                &src_path,
                &if spec.parents {
                    resolve_below(&stage.root, &dst_base.join(&kept), true)?
                } else {
                    dst_base.clone()
                },
                &skip,
            )?;
        } else if is_add && is_archive_name(&src_path) {
            std::fs::create_dir_all(&dst_base)?;
            let tmp_tar = tempfile::NamedTempFile::new()?;
            layer::decompress(&src_path, "", tmp_tar.path())?;
            layer::extract(tmp_tar.path(), &dst_base)?;
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

fn is_archive_name(p: &Path) -> bool {
    let s = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    s.ends_with(".tar") || s.ends_with(".tar.gz") || s.ends_with(".tgz") || s.ends_with(".tar.zst")
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
fn resolve_in_root(root: &Path, rel: &str, follow_last: bool) -> Result<PathBuf, Error> {
    safe_join_in_root(root, rel)?;
    // What is left to walk, last first.
    let mut todo: Vec<std::ffi::OsString> = Path::new(rel)
        .components()
        .rev()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_owned()),
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

/// `path`, below `root`, with its links resolved by [`resolve_in_root`].
fn resolve_below(root: &Path, path: &Path, follow_last: bool) -> Result<PathBuf, Error> {
    let rel = path.strip_prefix(root).unwrap_or(path);
    resolve_in_root(root, &rel.to_string_lossy().replace('\\', "/"), follow_last)
}

/// Copies files for one `COPY`: owners and modes as it asks, the names
/// of a hard-linked file linked again, and (from a stage or an image) file
/// flags, set at the end, since they may refuse what follows.
struct Copier {
    /// The root filesystem copied into, which its links stay inside.
    root: PathBuf,
    chown: Option<(u32, u32)>,
    chmod: Option<u32>,
    keep_flags: bool,
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
            linked: Default::default(),
            flags: Default::default(),
        }
    }

    /// Copies the tree `src_dir` to `dst_dir`, leaving out what `skip`
    /// names (by path below `root`).
    fn dir(
        &self,
        root: &Path,
        src_dir: &Path,
        dst_dir: &Path,
        skip: &dyn Fn(&str) -> bool,
    ) -> Result<(), Error> {
        std::fs::create_dir_all(dst_dir)?;
        apply_perms(dst_dir, self.chown, self.chmod)?;
        for entry in std::fs::read_dir(src_dir)? {
            let entry = entry?;
            let path = entry.path();
            let rel = path.strip_prefix(root).unwrap_or(&path);
            if skip(&rel.to_string_lossy().replace('\\', "/")) {
                continue;
            }
            let target = dst_dir.join(entry.file_name());
            if std::fs::symlink_metadata(&path)?.is_dir() {
                // A directory already there may be a link, as `/home` is.
                let target = resolve_below(&self.root, &target, true)?;
                self.dir(root, &path, &target, skip)?;
            } else {
                self.entry(&path, &target)?;
            }
        }
        // After its contents: a flag such as schg refuses them.
        self.keep_flags_of(src_dir, dst_dir)
    }

    /// Copies the file or link `src` to `dst`, replacing what is there.
    fn entry(&self, src: &Path, dst: &Path) -> Result<(), Error> {
        let meta = std::fs::symlink_metadata(src)?;
        if std::fs::symlink_metadata(dst).is_ok() {
            layer::remove_tree(dst)?;
        }
        if meta.file_type().is_symlink() {
            #[cfg(unix)]
            {
                let link = std::fs::read_link(src)?;
                std::os::unix::fs::symlink(link, dst)?;
            }
            #[cfg(windows)]
            let _ = std::fs::copy(src, dst);
        } else {
            if let Some(key) = layer::inode(&meta) {
                let first = self.linked.borrow().get(&key).cloned();
                if let Some(first) = first {
                    // The first copy has the owner, mode and flags.
                    std::fs::hard_link(first, dst)?;
                    return Ok(());
                }
                self.linked.borrow_mut().insert(key, dst.to_path_buf());
            }
            std::fs::copy(src, dst)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = self
                    .chmod
                    .unwrap_or_else(|| meta.permissions().mode() & 0o7777);
                std::fs::set_permissions(dst, std::fs::Permissions::from_mode(mode))?;
            }
        }
        apply_perms(dst, self.chown, self.chmod)?;
        self.keep_flags_of(src, dst)
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

fn apply_perms(
    path: &Path,
    chown_ids: Option<(u32, u32)>,
    chmod: Option<u32>,
) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        if let Some(mode) = chmod
            && let Ok(meta) = std::fs::symlink_metadata(path)
            && !meta.file_type().is_symlink()
        {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }
        if let Some((uid, gid)) = chown_ids
            && let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes())
        {
            unsafe {
                libc::lchown(c.as_ptr(), uid, gid);
            }
        }
    }
    let _ = (path, chown_ids, chmod);
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

/// `secs` since 1970 as an RFC 3339 UTC time, as image configs give it.
fn rfc3339(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Days to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
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
    let tag_ref = Reference::parse_local_tag(&opts.tag)?.to_string();
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
    cmd.arg(&opts.context_dir);
    let status = cmd
        .status()
        .await
        .map_err(|e| Error::Build(format!("running buildah: {e}")))?;
    if !status.success() {
        return Err(Error::Build(format!("buildah bud failed ({status})")));
    }

    let tmp = tempfile::Builder::new()
        .prefix("buildah-export")
        .tempdir_in(store.dir().join("tmp"))?;
    let archive = tmp.path().join("image.tar");
    let push_dest = format!("oci-archive:{}:{tag_ref}", archive.display());
    let status = tokio::process::Command::new("buildah")
        .args(["push", &tag_ref, &push_dest])
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
    use super::{pull_creds, rfc3339};

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
    }
}
