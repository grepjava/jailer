//! Local OCI image store supporting both ZFS dataset clones/snapshots
//! (matching `legion-image`) and a plain-directory fallback when ZFS is
//! unavailable or disabled, plus OCI archive export and registry push.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::oci::{
    self, Descriptor, Document, ImageConfig, Manifest, OCI_CONFIG, OCI_INDEX, OCI_LAYER_GZIP,
    OCI_MANIFEST, Platform,
};
use crate::registry::{Client, Credentials, sha256};
use crate::sys::Sys;
use crate::{Error, Reference, layer};

pub const SNAPSHOT: &str = "layer";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Image {
    /// The config's digest, as Podman's and Legion's image ids are.
    pub id: String,
    /// The manifest's digest.
    pub digest: String,
    /// Canonical references naming it.
    pub references: Vec<String>,
    /// Chain ids (hex, without `sha256:`), bottom layer first.
    pub layers: Vec<String>,
    pub config: ImageConfig,
    /// Compressed layer descriptors in order, for `push` and `export`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layer_descriptors: Vec<Descriptor>,
    /// References pulled with credentials, and who pulled them (Legion format).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub private: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageMode {
    /// Each layer is a ZFS dataset `<dataset>/<chain_hex>@layer`.
    Zfs(String),
    /// Each layer is a directory `<dir>/layers/<chain_hex>`.
    Directory,
}

pub struct Store {
    sys: Arc<dyn Sys>,
    mode: StorageMode,
    dir: PathBuf,
    client: Client,
    lock: tokio::sync::Mutex<()>,
    oses: Vec<&'static str>,
}

enum Source<'a> {
    Registry {
        client: &'a Client,
        reference: &'a Reference,
        creds: Option<&'a Credentials>,
    },
    Layout(&'a Path),
}

impl Source<'_> {
    async fn manifest(&self, oses: &[&str]) -> Result<(String, Manifest), Error> {
        match self {
            Source::Registry {
                client,
                reference,
                creds,
            } => client.manifest(reference, *creds, oses).await,
            Source::Layout(dir) => {
                let mut doc = Document::parse(&std::fs::read(dir.join("index.json"))?)?;
                let mut digest = String::new();
                for _ in 0..3 {
                    let Some(manifests) = &doc.manifests else {
                        return Ok((digest, doc.into_manifest()?));
                    };
                    let chosen = match manifests.as_slice() {
                        [one] => one,
                        many => oci::select(many, oses)?,
                    };
                    digest = chosen.digest.clone();
                    let bytes = std::fs::read(blob_path_in(dir, &digest)?)?;
                    check(&bytes, &digest, "manifest")?;
                    doc = Document::parse(&bytes)?;
                }
                Err(Error::Unsupported("indexes nested too deep".to_owned()))
            }
        }
    }

    async fn blob(&self, digest: &str, dest: &Path) -> Result<(), Error> {
        match self {
            Source::Registry {
                client,
                reference,
                creds,
            } => client.blob(reference, digest, dest, *creds).await,
            Source::Layout(dir) => {
                let from = blob_path_in(dir, digest)?;
                let dest = dest.to_owned();
                let digest = digest.to_owned();
                blocking(move || {
                    let mut hash = Sha256::new();
                    let mut input = std::fs::File::open(&from)?;
                    let mut out = std::fs::File::create(&dest)?;
                    std::io::copy(&mut input, &mut HashWriter(&mut out, &mut hash))?;
                    let got = format!("sha256:{:x}", hash.finalize());
                    if got != digest {
                        return Err(Error::Digest {
                            what: "blob".to_owned(),
                            expected: digest,
                            got,
                        });
                    }
                    Ok(())
                })
                .await
            }
        }
    }
}

struct HashWriter<'a>(&'a mut std::fs::File, &'a mut Sha256);

impl std::io::Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.0.write(buf)?;
        self.1.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

fn blob_path_in(dir: &Path, digest: &str) -> Result<PathBuf, Error> {
    let hex = hex_of(digest)?;
    Ok(dir.join("blobs").join("sha256").join(hex))
}

pub fn hex_of(digest: &str) -> Result<&str, Error> {
    digest
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| Error::Unsupported(format!("digest {digest:?}")))
}

fn check(bytes: &[u8], digest: &str, what: &str) -> Result<(), Error> {
    let got = sha256(bytes);
    if got != digest {
        return Err(Error::Digest {
            what: what.to_owned(),
            expected: digest.to_owned(),
            got,
        });
    }
    Ok(())
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))?
}

/// The chain ids of layers with these `diff_id`s, bottom first.
pub fn chain_ids(diff_ids: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in diff_ids {
        let id = match out.last() {
            None => d.clone(),
            Some(parent) => format!(
                "sha256:{:x}",
                Sha256::digest(format!("{parent} {d}").as_bytes())
            ),
        };
        out.push(id);
    }
    out
}

impl Store {
    /// Opens an image store in `dir`. When `zfs_dataset` is `Some(ds)`, uses
    /// ZFS dataset `ds` (creating it if missing); otherwise uses directory
    /// storage under `<dir>/layers`.
    pub fn open(
        sys: Arc<dyn Sys>,
        zfs_dataset: Option<&str>,
        dir: &Path,
        client: Client,
    ) -> Result<Store, Error> {
        let mode = match zfs_dataset {
            Some(ds) if !ds.is_empty() => {
                sys.zfs_create(ds, &[("mountpoint", "none")])?;
                StorageMode::Zfs(ds.to_owned())
            }
            _ => {
                std::fs::create_dir_all(dir.join("layers"))?;
                StorageMode::Directory
            }
        };
        let _ = std::fs::remove_dir_all(dir.join("tmp"));
        std::fs::create_dir_all(dir.join("tmp"))?;
        std::fs::create_dir_all(dir.join("mnt"))?;
        std::fs::create_dir_all(dir.join("blobs").join("sha256"))?;
        Ok(Store {
            sys,
            mode,
            dir: dir.to_owned(),
            client,
            lock: tokio::sync::Mutex::new(()),
            oses: vec!["freebsd"],
        })
    }

    pub fn with_linux(mut self, linux: bool) -> Store {
        self.oses = if linux {
            vec!["freebsd", "linux"]
        } else {
            vec!["freebsd"]
        };
        self
    }

    pub fn mode(&self) -> &StorageMode {
        &self.mode
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn sys(&self) -> &Arc<dyn Sys> {
        &self.sys
    }

    pub fn runs(&self, os: &str) -> bool {
        self.oses.contains(&os)
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join("index.json")
    }

    pub fn blob_path(&self, digest: &str) -> Result<PathBuf, Error> {
        blob_path_in(&self.dir, digest)
    }

    pub fn images(&self) -> Result<Vec<Image>, Error> {
        match std::fs::read(self.index_path()) {
            Ok(b) => Ok(serde_json::from_slice(&b)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, images: &[Image]) -> Result<(), Error> {
        let tmp = self.dir.join("index.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(images)?)?;
        std::fs::rename(tmp, self.index_path())?;
        Ok(())
    }

    /// Resolves an image by reference (`localhost/...`, `docker.io/...`, or
    /// short name) or by image ID prefix.
    pub fn get(&self, reference: &str) -> Result<Option<Image>, Error> {
        let images = self.images()?;
        // Try local tag first (`myapp` -> `localhost/myapp:latest`), then
        // standard Docker Hub canonicalization (`freebsd/freebsd-runtime:15.1`).
        let mut candidates = Vec::new();
        if let Ok(local) = Reference::parse_local_tag(reference) {
            candidates.push(local.to_string());
        }
        if let Ok(std_ref) = Reference::parse(reference) {
            let s = std_ref.to_string();
            if !candidates.contains(&s) {
                candidates.push(s);
            }
        }
        for cand in &candidates {
            if let Some(img) = images.iter().find(|i| i.references.contains(cand)) {
                return Ok(Some(img.clone()));
            }
        }
        // Also match by image id or hex prefix.
        let id_query = reference.strip_prefix("sha256:").unwrap_or(reference);
        if id_query.len() >= 6 && id_query.bytes().all(|b| b.is_ascii_hexdigit()) {
            let full_prefix = format!("sha256:{id_query}");
            if let Some(img) = images.iter().find(|i| i.id.starts_with(&full_prefix)) {
                return Ok(Some(img.clone()));
            }
        }
        Ok(None)
    }

    pub fn snapshot(&self, image: &Image) -> Option<String> {
        match &self.mode {
            StorageMode::Zfs(dataset) => {
                let top = image.layers.last()?;
                Some(format!("{dataset}/{top}@{SNAPSHOT}"))
            }
            StorageMode::Directory => None,
        }
    }

    pub fn layer_dir(&self, chain_hex: &str) -> PathBuf {
        self.dir.join("layers").join(chain_hex)
    }

    /// Prepares a writable rootfs from `image` at `root_path` (using ZFS
    /// clone `container_dataset` when in ZFS mode, or copying the top layer
    /// directory in Directory mode).
    pub fn prepare_rootfs(
        &self,
        image: &Image,
        root_path: &Path,
        container_dataset: Option<&str>,
    ) -> Result<(), Error> {
        let top = image
            .layers
            .last()
            .ok_or_else(|| Error::Unsupported("an image without layers".to_owned()))?;
        std::fs::create_dir_all(root_path)?;
        match (&self.mode, container_dataset) {
            (StorageMode::Zfs(ds_root), Some(target_ds)) => {
                if let Some((parent, _)) = target_ds.rsplit_once('/') {
                    self.sys.zfs_create(parent, &[("mountpoint", "none")])?;
                }
                let snap = format!("{ds_root}/{top}@{SNAPSHOT}");
                let mp = root_path.to_string_lossy().into_owned();
                self.sys
                    .zfs_clone(&snap, target_ds, &[("mountpoint", &mp)])?;
                Ok(())
            }
            (StorageMode::Zfs(ds_root), None) => {
                // Mount or clone temporarily to copy out to root_path
                let mnt = self.dir.join("mnt").join(format!("export-{top}"));
                let tmp_ds = format!("{ds_root}/tmp-{}", std::process::id());
                let _ = self.sys.zfs_destroy(&tmp_ds, true);
                std::fs::create_dir_all(&mnt)?;
                let snap = format!("{ds_root}/{top}@{SNAPSHOT}");
                let mp = mnt.to_string_lossy().into_owned();
                self.sys.zfs_clone(&snap, &tmp_ds, &[("mountpoint", &mp)])?;
                let res = layer::copy_tree(&mnt, root_path);
                let _ = self.sys.zfs_destroy(&tmp_ds, true);
                let _ = std::fs::remove_dir(&mnt);
                res
            }
            (StorageMode::Directory, _) => {
                let src = self.layer_dir(top);
                layer::copy_tree(&src, root_path)
            }
        }
    }

    /// Cleans up a writable rootfs prepared by [`Self::prepare_rootfs`].
    pub fn cleanup_rootfs(
        &self,
        root_path: &Path,
        container_dataset: Option<&str>,
    ) -> Result<(), Error> {
        if let (StorageMode::Zfs(_), Some(ds)) = (&self.mode, container_dataset)
            && !self.sys.zfs_list(ds)?.is_empty()
        {
            self.sys.zfs_destroy(ds, true)?;
        }
        if root_path.exists() {
            layer::remove_tree(root_path)?;
        }
        Ok(())
    }

    pub async fn pull(
        &self,
        reference: &str,
        creds: Option<&Credentials>,
        user: &str,
    ) -> Result<Image, Error> {
        let r = Reference::parse(reference)?;
        if r.is_local() {
            return Err(Error::NotFound(format!(
                "{r} is a local image: no registry serves it"
            )));
        }
        let _held = self.hold().await?;
        let source = Source::Registry {
            client: &self.client,
            reference: &r,
            creds,
        };
        self.ingest(&source, &r, creds.map(|_| user)).await
    }

    pub async fn import(&self, layout: &Path, reference: &str) -> Result<Image, Error> {
        let r = Reference::parse_local_tag(reference)?;
        let _held = self.hold().await?;
        self.ingest(&Source::Layout(layout), &r, None).await
    }

    pub async fn load(&self, archive: &Path, reference: Option<&str>) -> Result<Image, Error> {
        let _held = self.hold().await?;
        let tmp = tempfile::Builder::new()
            .prefix("load")
            .tempdir_in(self.dir.join("tmp"))?;
        let out = std::process::Command::new("tar")
            .arg("-xf")
            .arg(archive)
            .arg("-C")
            .arg(tmp.path())
            .output()?;
        if !out.status.success() {
            return Err(Error::Extract(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ));
        }
        let index = tmp.path().join("index.json");
        if !index.exists() {
            return Err(Error::Unsupported(
                "not an OCI archive (no index.json): save it with --format oci-archive".to_owned(),
            ));
        }
        let name = match reference {
            Some(r) => r.to_owned(),
            None => {
                let doc = Document::parse(&std::fs::read(&index)?)?;
                doc.manifests
                    .unwrap_or_default()
                    .iter()
                    .find_map(|m| {
                        m.annotations
                            .get("org.opencontainers.image.ref.name")
                            .cloned()
                    })
                    .ok_or_else(|| {
                        Error::Unsupported("the archive names no image: give a name".to_owned())
                    })?
            }
        };
        let r = Reference::parse_local_tag(&name)?;
        self.ingest(&Source::Layout(tmp.path()), &r, None).await
    }

    /// Commits a newly built layer tar + gzip blob on top of `parent_chain_hex`
    /// and caches the compressed blob in `blobs/sha256`.
    pub fn commit_built_layer(
        &self,
        pin: &Pin,
        parent_chain_hex: Option<&str>,
        chain_hex: &str,
        tar_path: &Path,
        gz_path: &Path,
        artifact: &layer::LayerArtifact,
    ) -> Result<Descriptor, Error> {
        pin.add(&[chain_hex, hex_of(&artifact.blob_digest)?])?;
        let blob_dest = self.blob_path(&artifact.blob_digest)?;
        if !blob_dest.exists() {
            std::fs::copy(gz_path, &blob_dest)?;
        }
        match &self.mode {
            StorageMode::Zfs(dataset) => {
                let ds = format!("{dataset}/{chain_hex}");
                let have = self.sys.zfs_snapshots(&ds)?.iter().any(|s| s == SNAPSHOT);
                if !have {
                    let parent_snap = parent_chain_hex.map(|p| format!("{dataset}/{p}@{SNAPSHOT}"));
                    let mnt = self.dir.join("mnt").join(chain_hex);
                    apply_zfs_layer(&*self.sys, &ds, parent_snap.as_deref(), &mnt, tar_path)?;
                }
            }
            StorageMode::Directory => {
                let dst = self.layer_dir(chain_hex);
                if !dst.exists() {
                    if let Some(p) = parent_chain_hex {
                        let parent_dir = self.layer_dir(p);
                        layer::copy_tree(&parent_dir, &dst)?;
                    } else {
                        std::fs::create_dir_all(&dst)?;
                    }
                    if let Err(e) = layer::apply(tar_path, &dst) {
                        let _ = layer::remove_tree(&dst);
                        return Err(e);
                    }
                }
            }
        }
        Ok(Descriptor {
            media_type: OCI_LAYER_GZIP.to_owned(),
            digest: artifact.blob_digest.clone(),
            size: artifact.blob_size,
            platform: None,
            annotations: BTreeMap::new(),
        })
    }

    /// Registers a built image in the store, writing its config and manifest
    /// blobs and updating `index.json`.
    pub async fn register_built_image(
        &self,
        pin: &Pin,
        reference: &Reference,
        config: ImageConfig,
        layers: Vec<String>,
        layer_descriptors: Vec<Descriptor>,
    ) -> Result<Image, Error> {
        let config_bytes = serde_json::to_vec_pretty(&config)?;
        let config_digest = sha256(&config_bytes);
        let config_blob = self.blob_path(&config_digest)?;
        pin.add(&[hex_of(&config_digest)?])?;
        std::fs::write(&config_blob, &config_bytes)?;

        let config_desc = Descriptor {
            media_type: OCI_CONFIG.to_owned(),
            digest: config_digest.clone(),
            size: config_bytes.len() as u64,
            platform: None,
            annotations: BTreeMap::new(),
        };
        let manifest = Manifest::new(config_desc, layer_descriptors.clone());
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        let manifest_digest = sha256(&manifest_bytes);
        let manifest_blob = self.blob_path(&manifest_digest)?;
        pin.add(&[hex_of(&manifest_digest)?])?;
        std::fs::write(&manifest_blob, &manifest_bytes)?;

        let image = Image {
            id: config_digest,
            digest: manifest_digest,
            references: vec![reference.to_string()],
            layers,
            config,
            layer_descriptors,
            private: BTreeMap::new(),
        };
        let _held = self.hold().await?;
        self.upsert_image(image, reference, None)
    }

    /// Starts a pin for a build: layers and blobs added to it survive a
    /// concurrent `rmi` until it is dropped.
    pub fn pin(&self) -> Result<Pin, Error> {
        let dir = self.dir.join("pins");
        std::fs::create_dir_all(&dir)?;
        let (file, path) = tempfile::Builder::new()
            .prefix("pin")
            .tempfile_in(&dir)?
            .keep()
            .map_err(|e| e.error)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(Pin { path, file })
    }

    /// Looks up a build step in the cache and pins its layer, atomically with
    /// respect to `rmi`. Entries whose layer or blob is gone are dropped.
    pub async fn cached_step(&self, pin: &Pin, key: &str) -> Result<Option<CachedStep>, Error> {
        let path = self.dir.join("cache").join(key);
        let _held = self.hold().await?;
        let Ok(text) = std::fs::read(&path) else {
            return Ok(None);
        };
        let Ok(step) = serde_json::from_slice::<CachedStep>(&text) else {
            let _ = std::fs::remove_file(&path);
            return Ok(None);
        };
        if let Some(l) = &step.layer {
            if !self.has_layer(&l.chain)? || !self.blob_path(&l.descriptor.digest)?.exists() {
                let _ = std::fs::remove_file(&path);
                return Ok(None);
            }
            pin.add(&[&l.chain, hex_of(&l.descriptor.digest)?])?;
        }
        Ok(Some(step))
    }

    /// Records the outcome of a build step under `key`.
    pub fn record_step(&self, key: &str, step: &CachedStep) -> Result<(), Error> {
        let dir = self.dir.join("cache");
        std::fs::create_dir_all(&dir)?;
        let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
        std::io::Write::write_all(&mut tmp, &serde_json::to_vec(step)?)?;
        tmp.persist(dir.join(key)).map_err(|e| e.error)?;
        Ok(())
    }

    fn has_layer(&self, chain_hex: &str) -> Result<bool, Error> {
        Ok(match &self.mode {
            StorageMode::Zfs(dataset) => self
                .sys
                .zfs_snapshots(&format!("{dataset}/{chain_hex}"))?
                .iter()
                .any(|s| s == SNAPSHOT),
            StorageMode::Directory => self.layer_dir(chain_hex).exists(),
        })
    }

    /// Looks up `reference` and pins its layers and blobs, atomically with
    /// respect to `rmi`.
    pub async fn pin_image(&self, pin: &Pin, reference: &str) -> Result<Option<Image>, Error> {
        let _held = self.hold().await?;
        let Some(image) = self.get(reference)? else {
            return Ok(None);
        };
        let mut names: Vec<&str> = image.layers.iter().map(String::as_str).collect();
        for d in [&image.id, &image.digest]
            .into_iter()
            .chain(image.layer_descriptors.iter().map(|d| &d.digest))
        {
            names.extend(hex_of(d).ok());
        }
        pin.add(&names)?;
        Ok(Some(image))
    }

    /// Exports `image_ref` as an OCI archive (`oci-archive` tar file) at
    /// `output_tar`, compatible with `legion image load`.
    pub fn export(
        &self,
        image_ref: &str,
        output_tar: &Path,
        override_name: Option<&str>,
    ) -> Result<Image, Error> {
        let mut image = self
            .get(image_ref)?
            .ok_or_else(|| Error::NotFound(format!("{image_ref}: image not found")))?;
        let ref_name = match override_name {
            Some(n) => Reference::parse_local_tag(n)?.to_string(),
            None => image
                .references
                .first()
                .cloned()
                .unwrap_or_else(|| image_ref.to_owned()),
        };

        let (_, manifest, config_bytes) = self.ensure_blobs(&mut image)?;
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        let manifest_digest = sha256(&manifest_bytes);

        let tmp = tempfile::Builder::new()
            .prefix("export")
            .tempdir_in(self.dir.join("tmp"))?;
        let blobs_dir = tmp.path().join("blobs").join("sha256");
        std::fs::create_dir_all(&blobs_dir)?;
        std::fs::write(
            tmp.path().join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )?;

        std::fs::write(
            blobs_dir.join(hex_of(&manifest.config.digest)?),
            &config_bytes,
        )?;
        std::fs::write(blobs_dir.join(hex_of(&manifest_digest)?), &manifest_bytes)?;
        for desc in &manifest.layers {
            let src_blob = self.blob_path(&desc.digest)?;
            let dst_blob = blobs_dir.join(hex_of(&desc.digest)?);
            if !dst_blob.exists() {
                std::fs::copy(&src_blob, &dst_blob)?;
            }
        }

        let mut annotations = BTreeMap::new();
        annotations.insert("org.opencontainers.image.ref.name".to_owned(), ref_name);
        let index_doc = Document {
            schema_version: 2,
            media_type: OCI_INDEX.to_owned(),
            manifests: Some(vec![Descriptor {
                media_type: OCI_MANIFEST.to_owned(),
                digest: manifest_digest,
                size: manifest_bytes.len() as u64,
                platform: Some(Platform {
                    architecture: if image.config.architecture.is_empty() {
                        oci::arch().to_owned()
                    } else {
                        image.config.architecture.clone()
                    },
                    os: if image.config.os.is_empty() {
                        "freebsd".to_owned()
                    } else {
                        image.config.os.clone()
                    },
                }),
                annotations,
            }]),
            config: None,
            layers: Vec::new(),
            annotations: BTreeMap::new(),
        };
        std::fs::write(
            tmp.path().join("index.json"),
            serde_json::to_vec_pretty(&index_doc)?,
        )?;

        if let Some(parent) = output_tar.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let tar_file = File::create(output_tar)?;
        let mut builder = tar::Builder::new(tar_file);
        builder.append_dir_all(".", tmp.path())?;
        builder.finish()?;
        Ok(image)
    }

    /// Pushes `image_ref` to `target_ref` in its OCI registry and returns the
    /// published manifest digest.
    pub async fn push(
        &self,
        image_ref: &str,
        target_ref: &Reference,
        creds: Option<&Credentials>,
    ) -> Result<String, Error> {
        if target_ref.is_local() {
            return Err(Error::Reference(format!(
                "{target_ref} is a localhost reference; give a registry destination (e.g. ghcr.io/me/app:tag)"
            )));
        }
        let (manifest, _) = self.push_blobs(image_ref, target_ref, creds).await?;
        self.client
            .push_manifest(target_ref, &manifest, creds)
            .await
    }

    /// Pushes an image index to `target` naming one image per platform.
    /// Each source is a local image, pushed by digest into the target's
    /// repository, or an image or index already in that repository.
    pub async fn push_index(
        &self,
        target: &Reference,
        sources: &[String],
        creds: Option<&Credentials>,
    ) -> Result<String, Error> {
        if target.is_local() {
            return Err(Error::Reference(format!(
                "{target} is a localhost reference; give a registry destination (e.g. ghcr.io/me/app:tag)"
            )));
        }
        let mut entries: Vec<Descriptor> = Vec::new();
        for src in sources {
            let found = if self.get(src)?.is_some() {
                let (manifest, platform) = self.push_blobs(src, target, creds).await?;
                let bytes = serde_json::to_vec_pretty(&manifest)?;
                let by_digest = Reference {
                    tag: None,
                    digest: Some(sha256(&bytes)),
                    ..target.clone()
                };
                let digest = self
                    .client
                    .push_manifest(&by_digest, &manifest, creds)
                    .await?;
                vec![Descriptor {
                    media_type: OCI_MANIFEST.to_owned(),
                    digest,
                    size: bytes.len() as u64,
                    platform: Some(platform),
                    annotations: BTreeMap::new(),
                }]
            } else {
                let r = Reference::parse(src)?;
                if r.registry != target.registry || r.repository != target.repository {
                    return Err(Error::Reference(format!(
                        "{src} is neither a local image nor in {}/{}: push it there first",
                        target.registry, target.repository
                    )));
                }
                self.client.describe(&r, creds).await?
            };
            for d in found {
                let p = d.platform.as_ref().ok_or_else(|| {
                    Error::Unsupported(format!("{src}: an index entry without a platform"))
                })?;
                if entries.iter().any(|e| e.platform == d.platform) {
                    return Err(Error::Unsupported(format!(
                        "two images for {}/{}: give one per platform",
                        p.os, p.architecture
                    )));
                }
                entries.push(d);
            }
        }
        let index = Document {
            schema_version: 2,
            media_type: OCI_INDEX.to_owned(),
            manifests: Some(entries),
            config: None,
            layers: Vec::new(),
            annotations: BTreeMap::new(),
        };
        self.client
            .push_document(target, serde_json::to_vec_pretty(&index)?, OCI_INDEX, creds)
            .await
    }

    /// Uploads `image_ref`'s layer and config blobs to `target_ref`'s
    /// repository, returning its manifest and platform.
    async fn push_blobs(
        &self,
        image_ref: &str,
        target_ref: &Reference,
        creds: Option<&Credentials>,
    ) -> Result<(Manifest, Platform), Error> {
        let mut image = self
            .get(image_ref)?
            .ok_or_else(|| Error::NotFound(format!("{image_ref}: image not found")))?;
        let (_, manifest, _) = self.ensure_blobs(&mut image)?;

        for desc in &manifest.layers {
            let blob = self.blob_path(&desc.digest)?;
            let uploaded = self
                .client
                .push_blob(target_ref, &desc.digest, &blob, creds)
                .await?;
            tracing::info!(
                digest = %desc.digest,
                uploaded,
                "layer blob pushed"
            );
        }
        let config_blob = self.blob_path(&manifest.config.digest)?;
        self.client
            .push_blob(target_ref, &manifest.config.digest, &config_blob, creds)
            .await?;
        let platform = Platform {
            architecture: if image.config.architecture.is_empty() {
                oci::arch().to_owned()
            } else {
                image.config.architecture.clone()
            },
            os: if image.config.os.is_empty() {
                "freebsd".to_owned()
            } else {
                image.config.os.clone()
            },
        };
        Ok((manifest, platform))
    }

    /// Ensures all layer blobs and the config blob for `image` exist in
    /// `blobs/sha256`, synthesizing any missing blob from the stored layer.
    fn ensure_blobs(&self, image: &mut Image) -> Result<(String, Manifest, Vec<u8>), Error> {
        let mut descriptors = Vec::new();
        for (i, chain_hex) in image.layers.iter().enumerate() {
            if let Some(existing) = image.layer_descriptors.get(i)
                && self.blob_path(&existing.digest)?.exists()
            {
                descriptors.push(existing.clone());
                continue;
            }
            // Synthesize blob from stored layer directory or ZFS dataset.
            let tmp = tempfile::Builder::new()
                .prefix("pack")
                .tempdir_in(self.dir.join("tmp"))?;
            let tar_path = tmp.path().join("layer.tar");
            let gz_path = tmp.path().join("layer.tar.gz");
            let art = match &self.mode {
                StorageMode::Directory => {
                    let dir = self.layer_dir(chain_hex);
                    layer::pack_directory_layer(&dir, &tar_path, &gz_path)?
                }
                StorageMode::Zfs(ds_root) => {
                    let mnt = tmp.path().join("mnt");
                    let tmp_ds = format!("{ds_root}/pack-{}", std::process::id());
                    let _ = self.sys.zfs_destroy(&tmp_ds, true);
                    std::fs::create_dir_all(&mnt)?;
                    let snap = format!("{ds_root}/{chain_hex}@{SNAPSHOT}");
                    let mp = mnt.to_string_lossy().into_owned();
                    self.sys.zfs_clone(&snap, &tmp_ds, &[("mountpoint", &mp)])?;
                    let res = layer::pack_directory_layer(&mnt, &tar_path, &gz_path);
                    let _ = self.sys.zfs_destroy(&tmp_ds, true);
                    res?
                }
            };
            let dest = self.blob_path(&art.blob_digest)?;
            std::fs::copy(&gz_path, &dest)?;
            if let Some(slot) = image.config.rootfs.diff_ids.get_mut(i) {
                *slot = art.diff_id;
            }
            descriptors.push(Descriptor {
                media_type: OCI_LAYER_GZIP.to_owned(),
                digest: art.blob_digest,
                size: art.blob_size,
                platform: None,
                annotations: BTreeMap::new(),
            });
        }
        image.layer_descriptors = descriptors.clone();
        let config_bytes = serde_json::to_vec_pretty(&image.config)?;
        let config_digest = sha256(&config_bytes);
        let config_blob = self.blob_path(&config_digest)?;
        if !config_blob.exists() {
            std::fs::write(&config_blob, &config_bytes)?;
        }
        let config_desc = Descriptor {
            media_type: OCI_CONFIG.to_owned(),
            digest: config_digest.clone(),
            size: config_bytes.len() as u64,
            platform: None,
            annotations: BTreeMap::new(),
        };
        let manifest = Manifest::new(config_desc, descriptors);
        Ok((config_digest, manifest, config_bytes))
    }

    async fn hold(&self) -> Result<Held<'_>, Error> {
        let inner = self.lock.lock().await;
        let path = self.dir.join("lock");
        let file = blocking(move || lock_file(&path)).await?;
        Ok(Held {
            _inner: inner,
            _file: file,
        })
    }

    async fn ingest(
        &self,
        source: &Source<'_>,
        r: &Reference,
        private: Option<&str>,
    ) -> Result<Image, Error> {
        let (digest, manifest) = source.manifest(&self.oses).await?;
        let tmp = tempfile::Builder::new()
            .prefix("pull")
            .tempdir_in(self.dir.join("tmp"))?;
        let config_path = tmp.path().join("config.json");
        source.blob(&manifest.config.digest, &config_path).await?;
        let config_bytes = std::fs::read(&config_path)?;
        let config_cache = self.blob_path(&manifest.config.digest)?;
        if !config_cache.exists() {
            std::fs::write(&config_cache, &config_bytes)?;
        }
        let config: ImageConfig = serde_json::from_slice(&config_bytes)
            .map_err(|e| Error::Unsupported(format!("the image config: {e}")))?;
        if !config.os.is_empty() && !self.oses.contains(&config.os.as_str()) {
            return Err(Error::Unsupported(format!(
                "{r} is an image for {}/{}; this host runs {} images",
                config.os,
                config.architecture,
                self.oses.join(" and ")
            )));
        }
        if config.rootfs.diff_ids.len() != manifest.layers.len() {
            return Err(Error::Unsupported(format!(
                "{r}: {} layers but {} diff_ids",
                manifest.layers.len(),
                config.rootfs.diff_ids.len()
            )));
        }
        let chains = chain_ids(&config.rootfs.diff_ids);
        let mut layers = Vec::new();
        let mut parent_hex: Option<String> = None;
        for (i, (desc, chain)) in manifest.layers.iter().zip(&chains).enumerate() {
            let hex = hex_of(chain)?.to_owned();
            let blob_cache = self.blob_path(&desc.digest)?;
            let have_layer = match &self.mode {
                StorageMode::Zfs(dataset) => {
                    let ds = format!("{dataset}/{hex}");
                    let sys = self.sys.clone();
                    blocking(move || Ok(sys.zfs_snapshots(&ds)?.iter().any(|s| s == SNAPSHOT)))
                        .await?
                }
                StorageMode::Directory => self.layer_dir(&hex).exists(),
            };
            if !have_layer || !blob_cache.exists() {
                let blob = tmp.path().join(format!("{i}.blob"));
                source.blob(&desc.digest, &blob).await?;
                if !blob_cache.exists() {
                    std::fs::copy(&blob, &blob_cache)?;
                }
                if !have_layer {
                    let tar = tmp.path().join(format!("{i}.tar"));
                    let diff_id = config.rootfs.diff_ids[i].clone();
                    {
                        let (blob, tar) = (blob.clone(), tar.clone());
                        blocking(move || layer::decompress(&blob, &diff_id, &tar)).await?;
                    }
                    let _ = std::fs::remove_file(&blob);
                    match &self.mode {
                        StorageMode::Zfs(dataset) => {
                            let ds = format!("{dataset}/{hex}");
                            let mnt = self.dir.join("mnt").join(&hex);
                            let sys = self.sys.clone();
                            let parent_snap = parent_hex
                                .as_ref()
                                .map(|p| format!("{dataset}/{p}@{SNAPSHOT}"));
                            blocking(move || {
                                apply_zfs_layer(&*sys, &ds, parent_snap.as_deref(), &mnt, &tar)
                            })
                            .await?;
                        }
                        StorageMode::Directory => {
                            let dst = self.layer_dir(&hex);
                            let parent_dir = parent_hex.as_ref().map(|p| self.layer_dir(p));
                            blocking(move || {
                                if let Some(p) = parent_dir {
                                    layer::copy_tree(&p, &dst)?;
                                } else {
                                    std::fs::create_dir_all(&dst)?;
                                }
                                if let Err(e) = layer::apply(&tar, &dst) {
                                    let _ = layer::remove_tree(&dst);
                                    return Err(e);
                                }
                                Ok(())
                            })
                            .await?;
                        }
                    }
                    tracing::info!(image = %r, layer = %hex, "layer added");
                }
            }
            layers.push(hex.clone());
            parent_hex = Some(hex);
        }
        let image = Image {
            id: manifest.config.digest.clone(),
            digest,
            references: vec![r.to_string()],
            layers,
            config,
            layer_descriptors: manifest.layers,
            private: BTreeMap::new(),
        };
        self.upsert_image(image, r, private)
    }

    fn upsert_image(
        &self,
        image: Image,
        r: &Reference,
        private: Option<&str>,
    ) -> Result<Image, Error> {
        let mut images = self.images()?;
        let name = r.to_string();
        for i in images.iter_mut().filter(|i| i.id != image.id) {
            i.references.retain(|n| *n != name);
            i.private.remove(&name);
        }
        let idx = match images.iter().position(|i| i.id == image.id) {
            Some(i) => {
                images[i].config = image.config;
                images[i].layers = image.layers;
                if !image.layer_descriptors.is_empty() {
                    images[i].layer_descriptors = image.layer_descriptors;
                }
                if !image.digest.is_empty() {
                    images[i].digest = image.digest;
                }
                i
            }
            None => {
                images.push(image);
                images.len() - 1
            }
        };
        let slot = &mut images[idx];
        if !slot.references.contains(&name) {
            slot.references.push(name.clone());
        }
        match private {
            Some(user) => {
                slot.private
                    .entry(name)
                    .or_default()
                    .insert(user.to_owned());
            }
            None => {
                slot.private.remove(&name);
            }
        }
        let out = slot.clone();
        images.retain(|i| !i.references.is_empty());
        self.save(&images)?;
        Ok(out)
    }

    pub async fn remove(&self, reference: &str) -> Result<bool, Error> {
        let target = self
            .get(reference)?
            .and_then(|i| i.references.first().cloned())
            .unwrap_or_else(|| reference.to_owned());
        let name = Reference::parse_local_tag(&target)
            .or_else(|_| Reference::parse(&target))?
            .to_string();
        let _held = self.hold().await?;
        let mut images = self.images()?;
        let mut found = false;
        for i in &mut images {
            let before = i.references.len();
            i.references.retain(|n| *n != name);
            i.private.remove(&name);
            found |= i.references.len() != before;
        }
        images.retain(|i| !i.references.is_empty());
        self.save(&images)?;
        self.prune_held(&images).await?;
        Ok(found)
    }

    /// Removes build cache entries whose layer is gone (all of them with
    /// `all_cache`), then the layers and blobs no image or cache entry
    /// uses. Returns the number of layers removed.
    pub async fn prune(&self, all_cache: bool) -> Result<usize, Error> {
        let _held = self.hold().await?;
        let cache_dir = self.dir.join("cache");
        if cache_dir.exists() {
            for e in std::fs::read_dir(&cache_dir)? {
                let path = e?.path();
                let keep = !all_cache
                    && std::fs::read(&path)
                        .ok()
                        .and_then(|b| serde_json::from_slice::<CachedStep>(&b).ok())
                        .is_some_and(|c| match &c.layer {
                            Some(l) => self.has_layer(&l.chain).unwrap_or(false),
                            None => true,
                        });
                if !keep {
                    std::fs::remove_file(&path)?;
                }
            }
        }
        let images = self.images()?;
        Ok(self.prune_held(&images).await?.len())
    }

    /// Layers and blobs the build cache names.
    fn cached_names(&self) -> Result<BTreeSet<String>, Error> {
        let mut names = BTreeSet::new();
        let dir = self.dir.join("cache");
        if !dir.exists() {
            return Ok(names);
        }
        for e in std::fs::read_dir(&dir)? {
            let Ok(bytes) = std::fs::read(e?.path()) else {
                continue;
            };
            if let Ok(CachedStep { layer: Some(l) }) = serde_json::from_slice(&bytes) {
                names.extend(hex_of(&l.descriptor.digest).map(str::to_owned));
                names.insert(l.chain);
            }
        }
        Ok(names)
    }

    async fn prune_held(&self, images: &[Image]) -> Result<Vec<String>, Error> {
        let cached = self.cached_names()?;
        self.prune_blobs(images, &cached)?;
        let used: BTreeSet<String> = images
            .iter()
            .flat_map(|i| i.layers.clone())
            .chain(cached)
            .collect();
        match &self.mode {
            StorageMode::Zfs(root) => {
                let sys = self.sys.clone();
                let root = root.clone();
                let dir = self.dir.clone();
                blocking(move || {
                    let prefix = format!("{root}/");
                    let listed = sys.zfs_list(&root)?;
                    let pinned = live_pins(&dir)?;
                    let mut unused: Vec<String> = listed
                        .into_iter()
                        .filter_map(|d| d.name.strip_prefix(&prefix).map(str::to_owned))
                        .filter(|n| !n.contains('/') && !used.contains(n) && !pinned.contains(n))
                        .collect();
                    let mut gone = Vec::new();
                    loop {
                        let before = unused.len();
                        unused.retain(|n| match sys.zfs_destroy(&format!("{root}/{n}"), true) {
                            Ok(()) => {
                                gone.push(n.clone());
                                false
                            }
                            Err(_) => true,
                        });
                        if unused.len() == before {
                            break;
                        }
                    }
                    Ok(gone)
                })
                .await
            }
            StorageMode::Directory => {
                let layers_dir = self.dir.join("layers");
                let mut gone = Vec::new();
                if layers_dir.exists() {
                    let listed = std::fs::read_dir(&layers_dir)?.collect::<Result<Vec<_>, _>>()?;
                    let pinned = live_pins(&self.dir)?;
                    for e in listed {
                        let name = e.file_name().to_string_lossy().into_owned();
                        if !used.contains(&name) && !pinned.contains(&name) {
                            layer::remove_tree(&e.path())?;
                            gone.push(name);
                        }
                    }
                }
                Ok(gone)
            }
        }
    }

    /// Removes cached blobs that no remaining image's manifest, config or
    /// layer descriptors name, nor the build cache.
    fn prune_blobs(&self, images: &[Image], cached: &BTreeSet<String>) -> Result<(), Error> {
        let mut used = cached.clone();
        for i in images {
            for d in [&i.id, &i.digest]
                .into_iter()
                .chain(i.layer_descriptors.iter().map(|d| &d.digest))
            {
                if let Ok(hex) = hex_of(d) {
                    used.insert(hex.to_owned());
                }
            }
        }
        let blobs_dir = self.dir.join("blobs").join("sha256");
        if !blobs_dir.exists() {
            return Ok(());
        }
        let listed = std::fs::read_dir(&blobs_dir)?.collect::<Result<Vec<_>, _>>()?;
        let pinned = live_pins(&self.dir)?;
        for e in listed {
            let name = e.file_name().to_string_lossy().into_owned();
            if !used.contains(&name) && !pinned.contains(&name) {
                std::fs::remove_file(e.path())?;
            }
        }
        Ok(())
    }
}

/// The outcome of a cached build step: the layer it added, if any.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedStep {
    pub layer: Option<CachedLayer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedLayer {
    /// Chain id (hex) of the stage after the step.
    pub chain: String,
    pub diff_id: String,
    pub descriptor: Descriptor,
}

/// Layers and blobs an unfinished build depends on, one name per line. The
/// build holds an exclusive lock on the file while it runs.
pub struct Pin {
    path: PathBuf,
    file: File,
}

impl Pin {
    fn add(&self, names: &[&str]) -> Result<(), Error> {
        use std::io::Write;
        let mut text = String::new();
        for n in names {
            text.push_str(n);
            text.push('\n');
        }
        (&self.file).write_all(text.as_bytes())?;
        Ok(())
    }
}

impl Drop for Pin {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Names pinned by running builds. Pins left by a build that died (their
/// lock is free) are removed. Callers must list what they might delete
/// before calling this, since a build pins a name before creating it.
fn live_pins(dir: &Path) -> Result<BTreeSet<String>, Error> {
    let mut names = BTreeSet::new();
    let pins = dir.join("pins");
    if !pins.exists() {
        return Ok(names);
    }
    for e in std::fs::read_dir(&pins)? {
        let path = e?.path();
        let Ok(file) = File::open(&path) else {
            continue;
        };
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                let _ = std::fs::remove_file(&path);
                continue;
            }
        }
        drop(file);
        if let Ok(text) = std::fs::read_to_string(&path) {
            names.extend(text.lines().map(str::to_owned));
        }
    }
    Ok(names)
}

struct Held<'a> {
    _inner: tokio::sync::MutexGuard<'a, ()>,
    _file: std::fs::File,
}

fn lock_file(path: &Path) -> Result<std::fs::File, Error> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(file)
}

fn apply_zfs_layer(
    sys: &dyn Sys,
    ds: &str,
    parent: Option<&str>,
    mnt: &Path,
    tar: &Path,
) -> Result<(), Error> {
    if !sys.zfs_list(ds)?.is_empty() {
        sys.zfs_destroy(ds, true)?;
    }
    std::fs::create_dir_all(mnt)?;
    let mountpoint = mnt.to_string_lossy().into_owned();
    let props = [("mountpoint", mountpoint.as_str())];
    match parent {
        Some(p) => sys.zfs_clone(p, ds, &props)?,
        None => sys.zfs_create(ds, &props)?,
    }
    let applied = layer::apply(tar, mnt)
        .and_then(|()| Ok(sys.zfs_set(ds, "mountpoint", "none")?))
        .and_then(|()| Ok(sys.zfs_snapshot(&format!("{ds}@{SNAPSHOT}"))?));
    if let Err(e) = applied {
        let _ = sys.zfs_destroy(ds, true);
        return Err(e);
    }
    let _ = std::fs::remove_dir(mnt);
    Ok(())
}
