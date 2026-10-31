//! The image store is Legion's (`legion_image::Store`), opened for a build
//! host: it keeps the blobs it pulls and builds, so images go out as they
//! came, and keeps its layers as directories where there is no ZFS. What is
//! jailer's own is the build cache: `<dir>/cache/<key>` names the layer a
//! `RUN` step left, kept (as a GC root) until the cache is trimmed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub use legion_image::{Image, Pin, StorageMode, Store, StoreLock, chain_ids, hex_of};

use crate::oci::Descriptor;
use crate::registry::Client;
use crate::sys::Sys;
use crate::{Error, Reference};

/// Opens the store in `dir`, its layers in ZFS dataset `zfs` (made if
/// missing) or, without one, in directories under `dir`.
pub fn open(
    sys: Arc<dyn Sys>,
    zfs: Option<&str>,
    dir: &Path,
    client: Client,
) -> Result<Store, Error> {
    let store = match zfs.filter(|ds| !ds.is_empty()) {
        Some(ds) => Store::open(sys, ds, dir, client)?,
        None => Store::open_directory(sys, dir, client)?,
    };
    Ok(store
        .keep_blobs()
        .with_gc_roots(Arc::new(|dir: &Path| cached_names(dir))))
}

/// Forgets the name `query` finds (`app:1` is `localhost/app:1`), then
/// removes what nothing uses any more. Returns whether it named an image.
pub async fn remove(store: &Store, query: &str) -> Result<bool, Error> {
    let name = match store.find(query)? {
        Some(i) => {
            let wanted = Reference::parse_local_tag(query)
                .ok()
                .map(|r| r.to_string())
                .filter(|n| i.references.contains(n))
                .or_else(|| {
                    Reference::parse(query)
                        .ok()
                        .map(|r| r.to_string())
                        .filter(|n| i.references.contains(n))
                });
            wanted.unwrap_or_else(|| i.references[0].clone())
        }
        None => Reference::parse_local_tag(query)?.to_string(),
    };
    Ok(store.remove(&name).await?)
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

fn cache_dir(store: &Store) -> PathBuf {
    store.dir().join("cache")
}

fn read_step(path: &Path) -> Option<CachedStep> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Looks up a build step in the cache and pins its layer, atomically with
/// respect to `rmi`. Entries whose layer or blob is gone are dropped.
pub async fn cached_step(store: &Store, pin: &Pin, key: &str) -> Result<Option<CachedStep>, Error> {
    let path = cache_dir(store).join(key);
    let _held = store.lock().await?;
    if !path.exists() {
        return Ok(None);
    }
    let Some(step) = read_step(&path) else {
        let _ = std::fs::remove_file(&path);
        return Ok(None);
    };
    if let Some(l) = &step.layer {
        if !store.has_layer(&l.chain)? || !store.blob_path(&l.descriptor.digest)?.exists() {
            let _ = std::fs::remove_file(&path);
            return Ok(None);
        }
        pin.add(&[&l.chain, hex_of(&l.descriptor.digest)?])?;
    }
    // The entry's mtime records its last use, for `trim_cache`.
    if let Ok(f) = File::options().append(true).open(&path) {
        let _ = f.set_modified(std::time::SystemTime::now());
    }
    Ok(Some(step))
}

/// Records the outcome of a build step under `key`.
pub fn record_step(store: &Store, key: &str, step: &CachedStep) -> Result<(), Error> {
    let dir = cache_dir(store);
    std::fs::create_dir_all(&dir)?;
    let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
    std::io::Write::write_all(&mut tmp, &serde_json::to_vec(step)?)?;
    tmp.persist(dir.join(key)).map_err(|e| e.error)?;
    Ok(())
}

/// Removes build cache entries whose layer is gone (all of them with
/// `all_cache`), then the layers and blobs no image or cache entry uses.
/// Returns the number of layers removed.
pub async fn prune(store: &Store, all_cache: bool) -> Result<usize, Error> {
    let held = store.lock().await?;
    if let Ok(listed) = std::fs::read_dir(cache_dir(store)) {
        for e in listed {
            let path = e?.path();
            let keep = !all_cache
                && read_step(&path).is_some_and(|c| match &c.layer {
                    Some(l) => store.has_layer(&l.chain).unwrap_or(false),
                    None => true,
                });
            if !keep {
                std::fs::remove_file(&path)?;
            }
        }
    }
    Ok(store.prune_locked(&held).await?.len())
}

/// Drops the least recently used build cache entries until the layers
/// only the cache keeps fit in `max` bytes, counted by compressed size,
/// then removes what nothing uses any more. Returns the entries dropped.
///
/// On ZFS a layer stays while a later cached layer is cloned from it, so
/// the space used may stay above `max` until that one is dropped too.
pub async fn trim_cache(store: &Store, max: u64) -> Result<usize, Error> {
    let held = store.lock().await?;
    let Ok(listed) = std::fs::read_dir(cache_dir(store)) else {
        return Ok(0);
    };
    let images = store.images()?;
    let in_images: BTreeSet<&str> = images
        .iter()
        .flat_map(|i| i.layers.iter().map(String::as_str))
        .collect();
    // Per layer: its size, the last use of an entry naming it, and those
    // entries.
    let mut layers: BTreeMap<String, (u64, std::time::SystemTime, Vec<PathBuf>)> = BTreeMap::new();
    for e in listed {
        let e = e?;
        let path = e.path();
        let Some(l) = read_step(&path).and_then(|c| c.layer) else {
            continue;
        };
        if in_images.contains(l.chain.as_str()) {
            continue;
        }
        let used = e.metadata()?.modified()?;
        let slot = layers
            .entry(l.chain)
            .or_insert((l.descriptor.size, used, Vec::new()));
        slot.1 = slot.1.max(used);
        slot.2.push(path);
    }
    let mut total: u64 = layers.values().map(|l| l.0).sum();
    let mut by_age: Vec<_> = layers.into_values().collect();
    by_age.sort_by_key(|l| l.1);
    let mut dropped = 0;
    for (size, _, paths) in by_age {
        if total <= max {
            break;
        }
        for p in paths {
            std::fs::remove_file(p)?;
            dropped += 1;
        }
        total -= size;
    }
    if dropped > 0 {
        store.prune_locked(&held).await?;
    }
    Ok(dropped)
}

/// Layers and blobs the build cache in store directory `dir` names: the
/// store's GC roots.
fn cached_names(dir: &Path) -> Result<BTreeSet<String>, legion_image::Error> {
    let mut names = BTreeSet::new();
    let Ok(listed) = std::fs::read_dir(dir.join("cache")) else {
        return Ok(names);
    };
    for e in listed {
        if let Some(CachedStep { layer: Some(l) }) = read_step(&e?.path()) {
            names.extend(hex_of(&l.descriptor.digest).map(str::to_owned));
            names.insert(l.chain);
        }
    }
    Ok(names)
}
