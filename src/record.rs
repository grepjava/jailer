//! A release's record: what an image was built from, what it is, and where
//! it went, for a deployment to name exactly that. `--record FILE` adds to
//! it at each step, and a step on another image or digest is refused, so a
//! moved tag cannot pass for what was recorded. It holds digests and names:
//! no secrets, build arguments or credentials. See docs/RELEASE-RECORD.md.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::containerfile::IgnoreMatcher;
use crate::store::Image;

/// Raised when a reader of the format would be misled by what is new in it.
pub const SCHEMA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub schema: u32,
    /// The jailer that wrote it last.
    pub builder: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<Built>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// The images it was built from, as they resolved.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bases: Vec<Base>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub published: Vec<Published>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified: Vec<Verified>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub archives: Vec<Archive>,
}

/// One image: its config's digest is not its manifest's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Built {
    pub config: String,
    pub manifest: String,
    pub platform: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub containerfile: String,
    /// Of the context as a build sees it: see [`context_digest`].
    pub context: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Base {
    pub reference: String,
    pub config: String,
    pub manifest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Published {
    /// As it was pushed: a tag, which may move.
    pub reference: String,
    /// What was pushed: a manifest, or an index with `platforms`.
    pub digest: String,
    /// The reference to deploy, which cannot move.
    pub pinned: String,
    /// An index's manifests, by platform.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub platforms: BTreeMap<String, String>,
    /// Where the signature of `digest` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A signature found good for `digest`. It records what was checked here: a
/// deployment's policy is its own to enforce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verified {
    pub digest: String,
    pub reference: String,
    /// The sha256 of the public key's file.
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Archive {
    pub file: String,
    pub sha256: String,
    pub manifest: String,
}

/// `path`'s contents as `sha256:...`.
pub fn file_digest(path: &Path) -> Result<String, Error> {
    let mut hash = Sha256::new();
    std::io::copy(&mut std::fs::File::open(path)?, &mut hash)?;
    Ok(format!("sha256:{:x}", hash.finalize()))
}

/// One digest for the files under `dir` a build can see: their relative
/// paths, kinds, modes where there are any, and contents, or a link's target.
/// What `ignore` leaves out does not count, nor do times or owners.
pub fn context_digest(dir: &Path, ignore: &IgnoreMatcher) -> Result<String, Error> {
    let mut entries = BTreeMap::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(at) = todo.pop() {
        for entry in std::fs::read_dir(&at)? {
            let path = entry?.path();
            let rel = path
                .strip_prefix(dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let meta = std::fs::symlink_metadata(&path)?;
            let left_out = ignore.is_ignored(&rel);
            if meta.is_dir() {
                if !left_out || ignore.may_reinclude(&rel) {
                    todo.push(path);
                }
            } else if left_out {
                continue;
            } else if meta.is_symlink() {
                let to = std::fs::read_link(&path)?;
                entries.insert(rel, format!("link {}", to.display()));
            } else {
                let mode = mode_of(&meta);
                entries.insert(rel, format!("file {mode} {}", file_digest(&path)?));
            }
        }
    }
    let mut hash = Sha256::new();
    for (rel, entry) in entries {
        hash.update(rel.as_bytes());
        hash.update(b"\0");
        hash.update(entry.as_bytes());
        hash.update(b"\n");
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;
    format!("{:o}", meta.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn mode_of(_: &std::fs::Metadata) -> String {
    "-".to_owned()
}

/// `os/arch`, with a variant if there is one, of an index's manifest entry.
fn platform_of(entry: &serde_json::Value) -> Option<String> {
    let p = entry.get("platform")?;
    let mut out = format!("{}/{}", p["os"].as_str()?, p["architecture"].as_str()?);
    if let Some(variant) = p["variant"].as_str() {
        out = format!("{out}/{variant}");
    }
    Some(out)
}

/// An index's manifests by platform, leaving out what names none, such as
/// attestations.
pub fn platforms_of(index: &serde_json::Value) -> BTreeMap<String, String> {
    index["manifests"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| Some((platform_of(m)?, m["digest"].as_str()?.to_owned())))
        .collect()
}

impl Default for Record {
    fn default() -> Self {
        Record {
            schema: SCHEMA,
            builder: builder(),
            image: None,
            source: None,
            bases: Vec::new(),
            published: Vec::new(),
            verified: Vec::new(),
            archives: Vec::new(),
        }
    }
}

fn builder() -> String {
    format!("jailer {}", env!("CARGO_PKG_VERSION"))
}

fn identity(image: &Image) -> Built {
    Built {
        config: image.id.clone(),
        manifest: image.digest.clone(),
        platform: format!("{}/{}", image.config.os, image.config.architecture),
    }
}

impl Record {
    /// A new record of a build, which replaces any before it.
    pub fn built(image: &Image, source: Source, mut bases: Vec<Base>) -> Self {
        bases.sort();
        bases.dedup();
        Record {
            image: Some(identity(image)),
            source: Some(source),
            bases,
            ..Record::default()
        }
    }

    /// The record at `path`, or a new one if there is none.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Record::default()),
            Err(e) => return Err(e.into()),
        };
        let bad = |why: String| Error::Runtime(format!("{}: {why}", path.display()));
        let record: Record = serde_json::from_str(&text).map_err(|e| bad(e.to_string()))?;
        if record.schema > SCHEMA {
            return Err(bad(format!(
                "a record of schema {}, newer than this jailer's {SCHEMA}",
                record.schema
            )));
        }
        Ok(record)
    }

    /// Writes it to `path`, whole or not at all.
    pub fn save(&mut self, path: &Path) -> Result<(), Error> {
        self.builder = builder();
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
        let mut tmp = tempfile::NamedTempFile::new_in(dir.unwrap_or(Path::new(".")))?;
        serde_json::to_writer_pretty(&mut tmp, self)
            .map_err(|e| Error::Runtime(format!("{}: {e}", path.display())))?;
        tmp.write_all(b"\n")?;
        tmp.persist(path).map_err(|e| Error::from(e.error))?;
        Ok(())
    }

    /// Refuses `image` if this record is of another: before a push, so a
    /// refused one sends nothing.
    pub fn check_image(&self, image: &Image) -> Result<(), Error> {
        match &self.image {
            Some(built) if built.config != image.id => Err(Error::Runtime(format!(
                "the record is of image {}, not {}",
                built.config, image.id
            ))),
            _ => Ok(()),
        }
    }

    /// `image`, which this record must be of, or come to be of.
    fn is_of(&mut self, image: &Image) -> Result<(), Error> {
        self.check_image(image)?;
        self.image.get_or_insert_with(|| identity(image));
        Ok(())
    }

    /// The image was pushed as `reference`, giving `digest`.
    pub fn pushed(
        &mut self,
        image: &Image,
        reference: String,
        digest: &str,
        pinned: String,
    ) -> Result<(), Error> {
        self.is_of(image)?;
        self.add_published(Published {
            reference,
            digest: digest.to_owned(),
            pinned,
            platforms: BTreeMap::new(),
            signature: None,
        });
        Ok(())
    }

    /// An index was pushed. One of its platforms must be this record's image,
    /// if it has one.
    pub fn pushed_index(
        &mut self,
        reference: String,
        digest: &str,
        pinned: String,
        platforms: BTreeMap<String, String>,
    ) -> Result<(), Error> {
        if let Some(built) = &self.image
            && !platforms.values().any(|d| *d == built.manifest)
        {
            return Err(Error::Runtime(format!(
                "the record's image {} is not in index {digest}",
                built.manifest
            )));
        }
        self.add_published(Published {
            reference,
            digest: digest.to_owned(),
            pinned,
            platforms,
            signature: None,
        });
        Ok(())
    }

    /// As it was pushed last: a push again of the same replaces it.
    fn add_published(&mut self, published: Published) {
        self.published
            .retain(|p| p.reference != published.reference || p.digest != published.digest);
        self.published.push(published);
    }

    /// Whether this record names `digest` as something it published.
    fn names(&self, digest: &str) -> bool {
        self.image.as_ref().is_some_and(|i| i.manifest == digest)
            || self
                .published
                .iter()
                .any(|p| p.digest == digest || p.platforms.values().any(|d| d == digest))
    }

    fn refuse_unknown(&self, digest: &str) -> Result<(), Error> {
        if self.names(digest) {
            return Ok(());
        }
        Err(Error::Runtime(format!(
            "the record does not name {digest}: the reference has moved, or is another image's"
        )))
    }

    /// `digest` was signed, the signature being at `signature`.
    pub fn signed(&mut self, digest: &str, signature: String) -> Result<(), Error> {
        self.refuse_unknown(digest)?;
        for p in self.published.iter_mut().filter(|p| p.digest == digest) {
            p.signature = Some(signature.clone());
        }
        Ok(())
    }

    /// A signature of `digest` was found good.
    pub fn verified(&mut self, digest: &str, reference: String, key: String) -> Result<(), Error> {
        self.refuse_unknown(digest)?;
        let verified = Verified {
            digest: digest.to_owned(),
            reference,
            key,
        };
        if !self.verified.contains(&verified) {
            self.verified.push(verified);
        }
        Ok(())
    }

    /// The image was written to the archive `file`.
    pub fn exported(&mut self, image: &Image, file: &Path) -> Result<(), Error> {
        self.is_of(image)?;
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.archives.retain(|a| a.file != name);
        self.archives.push(Archive {
            file: name,
            sha256: file_digest(file)?,
            manifest: image.digest.clone(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        Record {
            image: Some(Built {
                config: "sha256:c".to_owned(),
                manifest: "sha256:m".to_owned(),
                platform: "freebsd/amd64".to_owned(),
            }),
            ..Record::default()
        }
    }

    #[test]
    fn only_what_it_names_can_be_verified_or_signed() {
        let mut r = record();
        r.verified("sha256:m", "x".to_owned(), "k".to_owned())
            .unwrap();
        let moved = r.verified("sha256:other", "x".to_owned(), "k".to_owned());
        assert!(moved.unwrap_err().to_string().contains("has moved"));
        assert!(r.signed("sha256:other", "s".to_owned()).is_err());
        assert_eq!(r.verified.len(), 1);
    }

    #[test]
    fn an_index_must_hold_the_image_and_names_its_manifests() {
        let map = |d: &str| BTreeMap::from([("freebsd/amd64".to_owned(), d.to_owned())]);
        let mut r = record();
        let other = r.pushed_index("t".to_owned(), "sha256:i", "p".to_owned(), map("sha256:x"));
        assert!(other.is_err());
        r.pushed_index("t".to_owned(), "sha256:i", "p".to_owned(), map("sha256:m"))
            .unwrap();
        r.signed("sha256:i", "sig".to_owned()).unwrap();
        assert_eq!(r.published[0].signature.as_deref(), Some("sig"));
        // What was deployed may be the platform's manifest, or the index.
        r.verified("sha256:i", "x".to_owned(), "k".to_owned())
            .unwrap();
        r.verified("sha256:m", "x".to_owned(), "k".to_owned())
            .unwrap();
    }

    #[test]
    fn platforms_come_from_the_index() {
        let index = serde_json::json!({"manifests": [
            {"digest": "sha256:a", "platform": {"os": "freebsd", "architecture": "amd64"}},
            {"digest": "sha256:b", "platform": {"os": "freebsd", "architecture": "arm64", "variant": "v8"}},
            {"digest": "sha256:c"},
        ]});
        let got = platforms_of(&index);
        assert_eq!(got.len(), 2);
        assert_eq!(got["freebsd/amd64"], "sha256:a");
        assert_eq!(got["freebsd/arm64/v8"], "sha256:b");
    }

    #[test]
    fn a_context_digest_follows_what_a_build_sees() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = tmp.path();
        std::fs::create_dir(ctx.join("d")).unwrap();
        std::fs::write(ctx.join("d/f"), "one").unwrap();
        std::fs::write(ctx.join("x.log"), "ignored").unwrap();
        let ignore = IgnoreMatcher::parse("*.log\n");
        let digest = || context_digest(ctx, &ignore).unwrap();
        let first = digest();
        assert_eq!(digest(), first);
        std::fs::write(ctx.join("x.log"), "changed").unwrap();
        assert_eq!(digest(), first, "an ignored file does not count");
        std::fs::write(ctx.join("d/f"), "two").unwrap();
        let second = digest();
        assert_ne!(second, first);
        std::fs::rename(ctx.join("d/f"), ctx.join("d/g")).unwrap();
        assert_ne!(digest(), second, "nor does a file's name stay out of it");
    }

    #[test]
    fn a_newer_record_is_not_taken_for_this_one() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("r.json");
        assert_eq!(Record::open(&path).unwrap(), Record::default());
        let mut r = record();
        r.save(&path).unwrap();
        assert_eq!(Record::open(&path).unwrap(), r);
        r.schema = SCHEMA + 1;
        r.save(&path).unwrap();
        assert!(
            Record::open(&path)
                .unwrap_err()
                .to_string()
                .contains("newer")
        );
    }
}
