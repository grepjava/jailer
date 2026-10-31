//! `jailer build`: builds a FreeBSD OCI image from a `Containerfile`, either
//! natively in Rust (running `RUN` steps in ephemeral FreeBSD jails and
//! diffing layers) or via `buildah` when `--backend buildah` is selected,
//! followed by Legion compatibility verification.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use clap::ValueEnum;

use crate::check::{CheckReport, check_containerfile, check_image};
use crate::containerfile::{
    Containerfile, CopySpec, IgnoreMatcher, Instruction, RunMount, RunOptions, expand_vars,
    glob_match,
};
use crate::layer::{self, TreeState};
use crate::oci::{self, Descriptor, History, ImageConfig};
use crate::registry::{Credentials, sha256};
use crate::runtime::{BuildMount, JailRuntime, target};
use crate::store::{CachedLayer, CachedStep, Image, Pin, Store, chain_ids, hex_of};
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
    pub creds: Option<Credentials>,
    pub strict_lint: bool,
    /// Run every step instead of reusing cached `RUN` results.
    pub no_cache: bool,
    /// Contents of the secrets `RUN --mount=type=secret` can mount, by id.
    pub secrets: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct BuildResult {
    pub image: Image,
    pub report: CheckReport,
}

struct BuiltStage {
    name: Option<String>,
    root: PathBuf,
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

    let mut global_vars = BTreeMap::new();
    for (k, def) in &cf.global_args {
        if let Some(v) = opts.build_args.get(k).or(def.as_ref()) {
            global_vars.insert(k.clone(), v.clone());
        }
    }

    // Keeps the base images and new layers from a concurrent `rmi`.
    let pin = store.pin()?;
    let mut completed_stages: Vec<BuiltStage> = Vec::new();
    let mut cleanup_guard = StageCleanup(Vec::new());

    for stage_def in &cf.stages {
        let mut vars = global_vars.clone();
        let base_ref = expand_vars(&stage_def.base, &vars);
        let stage_root = build_tmp.path().join(format!("stage-{}", stage_def.index));
        std::fs::create_dir_all(&stage_root)?;
        cleanup_guard.0.push(stage_root.clone());

        let mut built = if base_ref.eq_ignore_ascii_case("scratch") {
            BuiltStage {
                name: stage_def.name.clone(),
                root: stage_root,
                config: ImageConfig {
                    architecture: oci::arch().to_owned(),
                    os: "freebsd".to_owned(),
                    ..Default::default()
                },
                layers: Vec::new(),
                descriptors: Vec::new(),
                shell: Vec::new(),
                cache_key: next_key("", &["scratch"]),
                tree: None,
            }
        } else if let Some(prev) = find_stage(&completed_stages, &base_ref) {
            layer::copy_tree(&prev.root, &stage_root)?;
            BuiltStage {
                name: stage_def.name.clone(),
                root: stage_root,
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
                    store.pull(&base_ref, opts.creds.as_ref(), "root").await?;
                    store.pin_image(&pin, &base_ref).await?.ok_or_else(|| {
                        Error::Build(format!(
                            "base image {base_ref} was removed during the build"
                        ))
                    })?
                }
            };
            store.prepare_rootfs(&base_img, &stage_root, None)?;
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
                config: cfg,
                layers: base_img.layers.clone(),
                descriptors: base_img.layer_descriptors.clone(),
                shell: Vec::new(),
                cache_key: next_key("", &["from", &base_img.id]),
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
        for (idx, sp) in stage_def.instructions.iter().enumerate() {
            let step_no = idx + 1;
            println!("Step {step_no}/{total}: {}", sp.raw);
            execute_instruction(
                store,
                &pin,
                opts.no_cache,
                &opts.secrets,
                runtime,
                &opts.context_dir,
                &ignore,
                &opts.build_args,
                &completed_stages,
                &mut built,
                &mut vars,
                sp,
                build_tmp.path(),
                step_no,
            )
            .await?;
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
    if final_layers.is_empty() {
        let tar_out = build_tmp.path().join("scratch.tar");
        let gz_out = build_tmp.path().join("scratch.tar.gz");
        let art = layer::pack_directory_layer(&final_stage.root, &tar_out, &gz_out)?;
        final_config.rootfs.diff_ids.push(art.diff_id.clone());
        let chains = chain_ids(&final_config.rootfs.diff_ids);
        let chain_hex = hex_of(chains.last().unwrap())?.to_owned();
        let desc = store.commit_built_layer(&pin, None, &chain_hex, &tar_out, &gz_out, &art)?;
        final_layers.push(chain_hex);
        final_descriptors.push(desc);
    }

    report.merge(check_image(&final_config, Some(&final_stage.root)));
    if opts.strict_lint && report.has_errors() {
        return Err(Error::Build(
            "Legion compatibility check reported errors".to_owned(),
        ));
    }

    let target_ref = Reference::parse_local_tag(&opts.tag)?;
    let image = store
        .register_built_image(
            &pin,
            &target_ref,
            final_config,
            final_layers,
            final_descriptors,
        )
        .await?;

    Ok(BuildResult { image, report })
}

struct StageCleanup(Vec<PathBuf>);

impl Drop for StageCleanup {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = layer::remove_tree(p);
        }
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

#[allow(clippy::too_many_arguments)]
async fn execute_instruction(
    store: &Arc<Store>,
    pin: &Pin,
    no_cache: bool,
    secrets: &BTreeMap<String, Vec<u8>>,
    runtime: &JailRuntime,
    context_dir: &Path,
    ignore: &IgnoreMatcher,
    cli_build_args: &BTreeMap<String, String>,
    completed_stages: &[BuiltStage],
    stage: &mut BuiltStage,
    vars: &mut BTreeMap<String, String>,
    sp: &crate::containerfile::SpannedInstruction,
    tmp_dir: &Path,
    step_no: usize,
) -> Result<(), Error> {
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
        Instruction::Healthcheck(_) | Instruction::Onbuild(_) => {
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
        Instruction::Copy(spec) => {
            let before = TreeState::capture_from(&stage.root, stage.tree.as_ref())?;
            apply_copy(
                context_dir,
                ignore,
                completed_stages,
                stage,
                vars,
                spec,
                false,
                sp.line,
            )?;
            commit_step_diff(store, pin, stage, &before, tmp_dir, step_no, &sp.raw)?;
            stage.cache_key = copy_key(stage, &sp.raw);
        }
        Instruction::Add(spec) => {
            let before = TreeState::capture_from(&stage.root, stage.tree.as_ref())?;
            apply_copy(
                context_dir,
                ignore,
                completed_stages,
                stage,
                vars,
                spec,
                true,
                sp.line,
            )?;
            commit_step_diff(store, pin, stage, &before, tmp_dir, step_no, &sp.raw)?;
            stage.cache_key = copy_key(stage, &sp.raw);
        }
        Instruction::Run(form, run_opts) => {
            // As in Docker, `$VAR` in RUN, CMD and ENTRYPOINT is left to the
            // shell: build args and ENV reach it through the environment.
            let argv = form.to_argv(&stage.shell);
            let mut run_env = stage.config.config.env.clone();
            for (k, v) in vars {
                if !run_env
                    .iter()
                    .any(|e| e.split('=').next() == Some(k.as_str()))
                {
                    run_env.push(format!("{k}={v}"));
                }
            }
            let mounts = RunMounts::prepare(
                store,
                context_dir,
                completed_stages,
                secrets,
                tmp_dir,
                step_no,
                run_opts,
                sp.line,
            )?;
            let key = next_key(
                &stage.cache_key,
                &[
                    "run",
                    &serde_json::to_string(&argv)?,
                    &serde_json::to_string(&run_env)?,
                    &stage.config.config.user,
                    &stage.config.config.working_dir,
                    &mounts.key,
                ],
            );
            let cached = if no_cache {
                None
            } else {
                store.cached_step(pin, &key).await?
            };
            match cached {
                Some(step) if apply_cached(store, stage, tmp_dir, step.layer.as_ref())? => {
                    println!(" ---> Using cache");
                    record_history(&mut stage.config, &sp.raw, step.layer.is_none());
                }
                _ => {
                    let before = TreeState::capture_from(&stage.root, stage.tree.as_ref())?;
                    runtime
                        .run_build_step(
                            &stage.root,
                            &argv,
                            &run_env,
                            &stage.config.config.user,
                            &stage.config.config.working_dir,
                            &mounts.mounts,
                            run_opts.no_network,
                        )
                        .await?;
                    drop(mounts);
                    let layer =
                        commit_step_diff(store, pin, stage, &before, tmp_dir, step_no, &sp.raw)?;
                    store.record_step(&key, &CachedStep { layer })?;
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
    mounts: Vec<BuildMount>,
    key: String,
    temp: Vec<PathBuf>,
}

impl RunMounts {
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        store: &Store,
        context_dir: &Path,
        completed_stages: &[BuiltStage],
        secrets: &BTreeMap<String, Vec<u8>>,
        tmp_dir: &Path,
        step_no: usize,
        opts: &RunOptions,
        line: usize,
    ) -> Result<Self, Error> {
        let mut out = RunMounts {
            mounts: Vec::new(),
            key: if opts.no_network {
                "network=none".to_owned()
            } else {
                String::new()
            },
            temp: Vec::new(),
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
                    out.mounts.push(BuildMount::Nullfs {
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
                    let (root, origin) = match from {
                        None => (context_dir, "context".to_owned()),
                        Some(name) => {
                            let st = find_stage(completed_stages, name).ok_or_else(|| {
                                Error::Build(format!(
                                    "line {line}: --mount from={name}: no earlier stage of that name"
                                ))
                            })?;
                            (st.root.as_path(), st.cache_key.clone())
                        }
                    };
                    let src = safe_join_in_root(root, source.trim_start_matches('/'))
                        .map_err(|e| Error::Build(format!("line {line}: {e}")))?;
                    if std::fs::symlink_metadata(&src).is_err() {
                        return Err(Error::Build(format!(
                            "line {line}: --mount source {source:?} not found"
                        )));
                    }
                    // A stage is named by its key; context files by their contents.
                    let contents = if from.is_some() {
                        origin
                    } else {
                        content_digest(&src)?
                    };
                    out.key
                        .push_str(&format!("\0bind {source} {target} {rw} {contents}"));
                    let mount_src = if *rw {
                        if src.is_dir() {
                            layer::copy_tree(&src, &scratch)?;
                        } else {
                            std::fs::copy(&src, &scratch)?;
                        }
                        out.temp.push(scratch);
                        out.temp.last().cloned().unwrap()
                    } else {
                        src
                    };
                    out.mounts.push(BuildMount::Nullfs {
                        source: mount_src,
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
                    out.mounts.push(BuildMount::Nullfs {
                        source: scratch,
                        target: target.clone(),
                        read_only: true,
                    });
                }
                RunMount::Tmpfs { target, size } => {
                    out.key.push_str(&format!("\0tmpfs {target}"));
                    out.mounts.push(BuildMount::Tmpfs {
                        target: target.clone(),
                        size: *size,
                    });
                }
            }
        }
        Ok(out)
    }
}

impl Drop for RunMounts {
    fn drop(&mut self) {
        for p in &self.temp {
            let _ = layer::remove_tree(p);
        }
    }
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

fn commit_step_diff(
    store: &Arc<Store>,
    pin: &Pin,
    stage: &mut BuiltStage,
    before: &TreeState,
    tmp_dir: &Path,
    step_no: usize,
    created_by: &str,
) -> Result<Option<CachedLayer>, Error> {
    let tar_out = tmp_dir.join(format!("step-{}-{step_no}.tar", stage.layers.len()));
    let gz_out = tmp_dir.join(format!("step-{}-{step_no}.tar.gz", stage.layers.len()));
    let (diff, after) = layer::create_diff_layer(before, &stage.root, &tar_out, &gz_out)?;
    stage.tree = Some(after);
    match diff {
        Some(art) => {
            let parent_hex = stage.layers.last().cloned();
            stage.config.rootfs.diff_ids.push(art.diff_id.clone());
            let chains = chain_ids(&stage.config.rootfs.diff_ids);
            let chain_hex = hex_of(chains.last().unwrap())?.to_owned();
            let desc = store.commit_built_layer(
                pin,
                parent_hex.as_deref(),
                &chain_hex,
                &tar_out,
                &gz_out,
                &art,
            )?;
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

#[allow(clippy::too_many_arguments)]
fn apply_copy(
    context_dir: &Path,
    ignore: &IgnoreMatcher,
    completed_stages: &[BuiltStage],
    stage: &mut BuiltStage,
    vars: &BTreeMap<String, String>,
    spec: &CopySpec,
    extract_archives: bool,
    line_no: usize,
) -> Result<(), Error> {
    let (src_root, use_ignore) = match &spec.from {
        Some(from_stage) => {
            let st = find_stage(completed_stages, from_stage).ok_or_else(|| {
                Error::Build(format!(
                    "line {line_no}: `COPY --from={from_stage}`: stage not found"
                ))
            })?;
            (st.root.as_path(), false)
        }
        None => (context_dir, true),
    };

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
    let dest_is_dir_hint =
        dest_expanded.ends_with('/') || dest_expanded == "." || spec.sources.len() > 1;

    let mut matched_sources = Vec::new();
    for raw_src in &spec.sources {
        let src_pat = expand_vars(raw_src, vars);
        let matches = resolve_source_paths(src_root, &src_pat, line_no)?;
        if matches.is_empty() {
            return Err(Error::Build(format!(
                "line {line_no}: source {src_pat:?} not found"
            )));
        }
        matched_sources.extend(matches);
    }

    for src_path in matched_sources {
        let rel_to_src = src_path.strip_prefix(src_root).unwrap_or(&src_path);
        let rel_str = rel_to_src.to_string_lossy().replace('\\', "/");
        if use_ignore && ignore.is_ignored(&rel_str) {
            continue;
        }
        let meta = std::fs::symlink_metadata(&src_path)?;
        if meta.is_dir() {
            let dst_dir = safe_join_in_root(&stage.root, &dest_in_container)?;
            copy_context_dir(
                src_root,
                &src_path,
                &dst_dir,
                use_ignore.then_some(ignore),
                chown_ids,
                spec.chmod,
            )?;
        } else {
            if extract_archives && is_archive_name(&src_path) {
                let dst_dir = safe_join_in_root(&stage.root, &dest_in_container)?;
                std::fs::create_dir_all(&dst_dir)?;
                let tmp_tar = tempfile::NamedTempFile::new()?;
                layer::decompress(&src_path, "", tmp_tar.path())?;
                layer::extract(tmp_tar.path(), &dst_dir)?;
                continue;
            }
            let dst_base = safe_join_in_root(&stage.root, &dest_in_container)?;
            let final_dst = if dest_is_dir_hint || dst_base.is_dir() {
                std::fs::create_dir_all(&dst_base)?;
                dst_base.join(
                    src_path
                        .file_name()
                        .ok_or_else(|| Error::Build(format!("line {line_no}: invalid source")))?,
                )
            } else {
                if let Some(parent) = dst_base.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                dst_base
            };
            copy_single_entry(&src_path, &final_dst, chown_ids, spec.chmod)?;
        }
    }
    Ok(())
}

fn is_archive_name(p: &Path) -> bool {
    let s = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    s.ends_with(".tar") || s.ends_with(".tar.gz") || s.ends_with(".tgz") || s.ends_with(".tar.zst")
}

fn resolve_source_paths(
    src_root: &Path,
    pattern: &str,
    line_no: usize,
) -> Result<Vec<PathBuf>, Error> {
    let trimmed = pattern.trim_start_matches('/');
    if trimmed.is_empty() || trimmed == "." {
        return Ok(vec![src_root.to_path_buf()]);
    }
    let clean = safe_join_in_root(src_root, trimmed)
        .map_err(|e| Error::Build(format!("line {line_no}: {e}")))?;
    if !trimmed.contains(['*', '?']) {
        if std::fs::symlink_metadata(&clean).is_ok() {
            return Ok(vec![clean]);
        }
        return Ok(Vec::new());
    }
    let Some(parent) = clean.parent() else {
        return Ok(Vec::new());
    };
    let Some(file_pat) = clean.file_name().and_then(|f| f.to_str()) else {
        return Ok(Vec::new());
    };
    if !parent.is_dir() {
        return Ok(Vec::new());
    }
    let mut matches = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(s) = name.to_str()
            && glob_match(file_pat, s)
        {
            matches.push(entry.path());
        }
    }
    matches.sort();
    Ok(matches)
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

fn copy_context_dir(
    context_root: &Path,
    src_dir: &Path,
    dst_dir: &Path,
    ignore: Option<&IgnoreMatcher>,
    chown_ids: Option<(u32, u32)>,
    chmod: Option<u32>,
) -> Result<(), Error> {
    std::fs::create_dir_all(dst_dir)?;
    apply_perms(dst_dir, chown_ids, chmod)?;
    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(context_root).unwrap_or(&path);
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if let Some(ig) = ignore
            && ig.is_ignored(&rel_str)
        {
            continue;
        }
        let target = dst_dir.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            copy_context_dir(context_root, &path, &target, ignore, chown_ids, chmod)?;
        } else {
            copy_single_entry(&path, &target, chown_ids, chmod)?;
        }
    }
    Ok(())
}

fn copy_single_entry(
    src: &Path,
    dst: &Path,
    chown_ids: Option<(u32, u32)>,
    chmod: Option<u32>,
) -> Result<(), Error> {
    let meta = std::fs::symlink_metadata(src)?;
    if dst.exists() || std::fs::symlink_metadata(dst).is_ok() {
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
        std::fs::copy(src, dst)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = chmod.unwrap_or_else(|| meta.permissions().mode() & 0o7777);
            std::fs::set_permissions(dst, std::fs::Permissions::from_mode(mode))?;
        }
    }
    apply_perms(dst, chown_ids, chmod)?;
    Ok(())
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
    store.load(&archive, Some(&tag_ref)).await
}
