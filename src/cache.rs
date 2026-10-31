//! A build cache kept in a registry: `build --cache-to REF` pushes what this
//! build's `RUN` steps left, and `--cache-from REF` lets a build on another
//! host use it. The cache is an OCI manifest whose layers are the steps'
//! layer blobs and whose config maps each step's cache key to its layer.
//! Only the manifest and config are read up front; a layer is downloaded
//! when a step finds it, and becomes a local layer and cache entry.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::layer::{self, LayerArtifact};
use crate::oci::{Descriptor, Manifest};
use crate::registry::{Client, Credentials, sha256};
use crate::store::{CachedLayer, CachedStep, Pin, Store, chain_ids, hex_of};
use crate::{Error, Reference};

/// The cache config's media type.
pub const CONFIG_TYPE: &str = "application/vnd.jailer.build-cache.config.v1+json";

/// A registry and repository, and the credentials for it.
#[derive(Debug, Clone)]
pub struct Remote {
    pub reference: Reference,
    pub creds: Option<Credentials>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheConfig {
    steps: BTreeMap<String, Entry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    /// The step's layer: its index in the manifest's layers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    layer: Option<usize>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    diff_id: String,
}

/// Steps found in the `--cache-from` caches, by cache key.
#[derive(Default)]
pub struct Imported {
    steps: BTreeMap<String, (usize, Option<(Descriptor, String)>)>,
    remotes: Vec<Remote>,
}

impl Imported {
    /// Reads the caches `remotes` name; one that is missing or unreadable
    /// is left out with a warning, the earlier ones winning for a key.
    pub async fn read(client: &Client, remotes: &[Remote]) -> Imported {
        let mut out = Imported {
            remotes: remotes.to_vec(),
            ..Default::default()
        };
        for (i, remote) in remotes.iter().enumerate() {
            match read_one(client, remote).await {
                Ok(steps) => {
                    for (key, step) in steps {
                        out.steps.entry(key).or_insert((i, step));
                    }
                }
                Err(e) => eprintln!(
                    "warning: --cache-from {}: {e}; building without it",
                    remote.reference
                ),
            }
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Makes the step `key` a local cache entry, if a cache has it and its
    /// layer follows `diff_ids` (the stage's so far, `parent` its top
    /// layer). Returns whether it did.
    pub async fn fetch(
        &self,
        store: &Store,
        pin: &Pin,
        key: &str,
        diff_ids: &[String],
        parent: Option<&str>,
        tmp_dir: &Path,
    ) -> Result<bool, Error> {
        let Some((from, step)) = self.steps.get(key) else {
            return Ok(false);
        };
        let Some((descriptor, diff_id)) = step else {
            crate::store::record_step(store, key, &CachedStep { layer: None })?;
            return Ok(true);
        };
        let mut all = diff_ids.to_vec();
        all.push(diff_id.clone());
        let chain = hex_of(chain_ids(&all).last().expect("a layer"))?.to_owned();
        let remote = &self.remotes[*from];
        let blob = tmp_dir.join("cache-blob");
        let tar = tmp_dir.join("cache.tar");
        let made = async {
            store
                .client()
                .blob(
                    &remote.reference,
                    &descriptor.digest,
                    &blob,
                    remote.creds.as_ref(),
                )
                .await?;
            layer::decompress(&blob, diff_id, &tar)?;
            let art = LayerArtifact {
                diff_id: diff_id.clone(),
                blob_digest: descriptor.digest.clone(),
                blob_size: descriptor.size,
            };
            store
                .commit_built_layer(pin, parent, &chain, &tar, &blob, &art)
                .await?;
            Ok::<_, Error>(())
        }
        .await;
        let _ = std::fs::remove_file(&blob);
        let _ = std::fs::remove_file(&tar);
        made?;
        crate::store::record_step(
            store,
            key,
            &CachedStep {
                layer: Some(CachedLayer {
                    chain,
                    diff_id: diff_id.clone(),
                    descriptor: descriptor.clone(),
                }),
            },
        )?;
        Ok(true)
    }
}

async fn read_one(
    client: &Client,
    remote: &Remote,
) -> Result<BTreeMap<String, Option<(Descriptor, String)>>, Error> {
    let r = &remote.reference;
    let (_, doc) = client
        .document(r, r.target(), remote.creds.as_ref())
        .await?;
    let manifest = doc.into_manifest()?;
    if manifest.config.media_type != CONFIG_TYPE {
        return Err(Error::Build(format!(
            "not a jailer build cache (its config is {})",
            manifest.config.media_type
        )));
    }
    let tmp = tempfile::NamedTempFile::new()?;
    client
        .blob(
            r,
            &manifest.config.digest,
            tmp.path(),
            remote.creds.as_ref(),
        )
        .await?;
    let config: CacheConfig = serde_json::from_slice(&std::fs::read(tmp.path())?)?;
    let mut out = BTreeMap::new();
    for (key, entry) in config.steps {
        let layer = match entry.layer {
            Some(i) => match manifest.layers.get(i) {
                Some(d) if !entry.diff_id.is_empty() => Some((d.clone(), entry.diff_id)),
                _ => continue,
            },
            None => None,
        };
        out.insert(key, layer);
    }
    Ok(out)
}

/// Pushes `steps`, this build's `RUN` steps by cache key, to `remote`.
pub async fn export(
    client: &Client,
    store: &Store,
    remote: &Remote,
    steps: &[(String, CachedStep)],
) -> Result<String, Error> {
    let r = &remote.reference;
    let creds = remote.creds.as_ref();
    let mut config = CacheConfig::default();
    let mut layers: Vec<Descriptor> = Vec::new();
    for (key, step) in steps {
        let entry = match &step.layer {
            Some(l) => {
                let index = match layers.iter().position(|d| d.digest == l.descriptor.digest) {
                    Some(i) => i,
                    None => {
                        client
                            .push_blob(
                                r,
                                &l.descriptor.digest,
                                &store.blob_path(&l.descriptor.digest)?,
                                creds,
                            )
                            .await?;
                        layers.push(Descriptor {
                            platform: None,
                            annotations: BTreeMap::new(),
                            ..l.descriptor.clone()
                        });
                        layers.len() - 1
                    }
                };
                Entry {
                    layer: Some(index),
                    diff_id: l.diff_id.clone(),
                }
            }
            None => Entry {
                layer: None,
                diff_id: String::new(),
            },
        };
        config.steps.insert(key.clone(), entry);
    }
    let bytes = serde_json::to_vec_pretty(&config)?;
    let digest = sha256(&bytes);
    let tmp = tempfile::NamedTempFile::new()?;
    std::fs::write(tmp.path(), &bytes)?;
    client.push_blob(r, &digest, tmp.path(), creds).await?;
    let manifest = Manifest::new(
        Descriptor {
            media_type: CONFIG_TYPE.to_owned(),
            digest,
            size: bytes.len() as u64,
            platform: None,
            annotations: BTreeMap::new(),
        },
        layers,
    );
    Ok(client.push_manifest(r, &manifest, creds).await?)
}
