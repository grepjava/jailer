//! Creating OCI image layers during `jailer build`: snapshots of a root
//! file system, compared to write what a step changed (and `.wh.`
//! whiteouts for what it removed) as a deterministic tar. Applying layers,
//! and copying and removing trees with their file flags, is
//! `legion_image::layer`'s, re-exported here.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Component, Path};

use sha2::{Digest, Sha256};

use crate::Error;

pub use legion_image::layer::{
    LayerArtifact, Whiteout, apply, apply_whiteouts, compress, copy_tree, decompress, extract,
    remove_tree, whiteouts,
};

const WHITEOUT: &str = ".wh.";

/// Fingerprint of a single entry in a rootfs directory tree, used to detect
/// additions, modifications, and deletions between build steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMeta {
    pub kind: EntryKind,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub size: u64,
    pub digest_or_link: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Dir,
    File,
    Symlink,
}

#[derive(Debug, Clone, Default)]
pub struct TreeState {
    pub entries: BTreeMap<String, EntryMeta>,
    /// Each file's stat fingerprint when it was hashed.
    stamps: BTreeMap<String, Stamp>,
}

/// What changes whenever a file's contents could have: a write updates
/// ctime, which programs cannot set back.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    ino: u64,
}

impl Stamp {
    #[cfg(unix)]
    fn of(meta: &std::fs::Metadata) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        Some(Self {
            size: meta.size(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
            ino: meta.ino(),
        })
    }

    #[cfg(not(unix))]
    fn of(_: &std::fs::Metadata) -> Option<Self> {
        None
    }
}

impl TreeState {
    /// Captures the state of all files, directories, and symlinks under `root`.
    pub fn capture(root: &Path) -> Result<Self, Error> {
        Self::capture_from(root, None)
    }

    /// Like `capture`, but reuses `prev`'s digest for files whose stat
    /// fingerprint has not changed since `prev` was taken of the same tree.
    pub fn capture_from(root: &Path, prev: Option<&TreeState>) -> Result<Self, Error> {
        let mut state = Self::default();
        // A file changed within a second of this capture could change again
        // without its stamp changing on a filesystem with coarse timestamps,
        // so its stamp is not kept and it is hashed again next time.
        let racy_after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
            - 1;
        if root.exists() {
            walk_capture(root, root, prev, racy_after, &mut state)?;
        }
        Ok(state)
    }
}

fn walk_capture(
    root: &Path,
    dir: &Path,
    prev: Option<&TreeState>,
    racy_after: i64,
    out: &mut TreeState,
) -> Result<(), Error> {
    let mut children: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|e| e.file_name());
    for entry in children {
        let full = entry.path();
        let rel = full
            .strip_prefix(root)
            .map_err(|e| Error::Extract(e.to_string()))?;
        let rel_str = normalize_rel(rel);
        // Skip pseudo mounts inside a build root if any exist.
        if rel_str == "dev" || rel_str.starts_with("dev/") {
            continue;
        }
        let meta = std::fs::symlink_metadata(&full)?;
        let (mode, uid, gid) = meta_owner_mode(&meta);
        if meta.file_type().is_symlink() {
            let link = std::fs::read_link(&full)?
                .to_string_lossy()
                .replace('\\', "/");
            out.entries.insert(
                rel_str,
                EntryMeta {
                    kind: EntryKind::Symlink,
                    mode,
                    uid,
                    gid,
                    size: 0,
                    digest_or_link: link,
                },
            );
        } else if meta.is_dir() {
            out.entries.insert(
                rel_str,
                EntryMeta {
                    kind: EntryKind::Dir,
                    mode,
                    uid,
                    gid,
                    size: 0,
                    digest_or_link: String::new(),
                },
            );
            walk_capture(root, &full, prev, racy_after, out)?;
        } else if meta.is_file() {
            let stamp = Stamp::of(&meta);
            let reused = prev.and_then(|p| {
                let same = stamp.is_some() && p.stamps.get(&rel_str) == stamp.as_ref();
                same.then(|| p.entries.get(&rel_str))
                    .flatten()
                    .filter(|e| e.kind == EntryKind::File)
                    .map(|e| e.digest_or_link.clone())
            });
            let digest = match reused {
                Some(d) => d,
                None => file_sha256(&full)?,
            };
            if let Some(stamp) = stamp.filter(|s| s.ctime.0 < racy_after) {
                out.stamps.insert(rel_str.clone(), stamp);
            }
            out.entries.insert(
                rel_str,
                EntryMeta {
                    kind: EntryKind::File,
                    mode,
                    uid,
                    gid,
                    size: meta.len(),
                    digest_or_link: digest,
                },
            );
        }
    }
    Ok(())
}

fn file_sha256(path: &Path) -> Result<String, Error> {
    let mut f = BufReader::new(File::open(path)?);
    let mut h = Sha256::new();
    let mut buf = [0u8; 32768];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

#[cfg(unix)]
fn meta_owner_mode(meta: &std::fs::Metadata) -> (u32, u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (
        meta.mode() & 0o7777,
        u64::from(meta.uid()),
        u64::from(meta.gid()),
    )
}

#[cfg(not(unix))]
fn meta_owner_mode(meta: &std::fs::Metadata) -> (u32, u64, u64) {
    let mode = if meta.permissions().readonly() {
        0o555
    } else if meta.is_dir() {
        0o755
    } else {
        0o644
    };
    (mode, 0, 0)
}

fn normalize_rel(p: &Path) -> String {
    p.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Computes the filesystem difference between `before` and the current
/// `after_root`, writes an uncompressed tar to `tar_out` and a gzip-compressed
/// blob to `gz_out`, and returns the layer digests (`None` if nothing changed)
/// with the state of `after_root`, to start the next step's diff from.
pub fn create_diff_layer(
    before: &TreeState,
    after_root: &Path,
    tar_out: &Path,
    gz_out: &Path,
) -> Result<(Option<LayerArtifact>, TreeState), Error> {
    let after = TreeState::capture_from(after_root, Some(before))?;
    let mut deleted: Vec<String> = Vec::new();
    for old_path in before.entries.keys() {
        if !after.entries.contains_key(old_path) {
            // Only emit a whiteout if its parent directory was not also deleted.
            let parent_deleted = Path::new(old_path)
                .parent()
                .map(normalize_rel)
                .filter(|p| !p.is_empty())
                .is_some_and(|p| !after.entries.contains_key(&p));
            if !parent_deleted {
                deleted.push(old_path.clone());
            }
        }
    }

    let mut changed: Vec<String> = Vec::new();
    for (path, meta) in &after.entries {
        if before.entries.get(path) != Some(meta) {
            changed.push(path.clone());
        }
    }

    if deleted.is_empty() && changed.is_empty() {
        return Ok((None, after));
    }

    // Ensure parent directories of changed or deleted entries are included
    // so tar extraction has the directory hierarchy.
    let mut dirs_needed = std::collections::BTreeSet::new();
    for p in changed.iter().chain(deleted.iter()) {
        let mut cur = Path::new(p).parent();
        while let Some(parent) = cur {
            let rel = normalize_rel(parent);
            if rel.is_empty() {
                break;
            }
            if !changed.contains(&rel) {
                dirs_needed.insert(rel);
            }
            cur = parent.parent();
        }
    }

    {
        let tar_file = BufWriter::new(File::create(tar_out)?);
        let mut builder = tar::Builder::new(tar_file);
        builder.follow_symlinks(false);

        for dir_rel in &dirs_needed {
            if let Some(meta) = after.entries.get(dir_rel)
                && meta.kind == EntryKind::Dir
            {
                append_path_to_tar(&mut builder, after_root, dir_rel, meta)?;
            }
        }

        for del_rel in &deleted {
            let p = Path::new(del_rel);
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| Error::Extract(format!("bad deleted path {del_rel}")))?;
            let wh_rel = match p.parent().map(normalize_rel).filter(|s| !s.is_empty()) {
                Some(parent) => format!("{parent}/{WHITEOUT}{name}"),
                None => format!("{WHITEOUT}{name}"),
            };
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o600);
            header.set_uid(0);
            header.set_gid(0);
            header.set_size(0);
            header.set_mtime(0);
            header.set_cksum();
            builder.append_data(&mut header, &wh_rel, std::io::empty())?;
        }

        for ch_rel in &changed {
            let meta = &after.entries[ch_rel];
            append_path_to_tar(&mut builder, after_root, ch_rel, meta)?;
        }

        builder.finish()?;
    }

    let art = compress(tar_out, gz_out)?;
    Ok((Some(art), after))
}

/// Packs an entire root directory `root` into an OCI layer (`tar_out` and
/// `gz_out`), returning its `diff_id` and compressed `blob_digest`.
pub fn pack_directory_layer(
    root: &Path,
    tar_out: &Path,
    gz_out: &Path,
) -> Result<LayerArtifact, Error> {
    let state = TreeState::capture(root)?;
    {
        let tar_file = BufWriter::new(File::create(tar_out)?);
        let mut builder = tar::Builder::new(tar_file);
        builder.follow_symlinks(false);
        for (rel, meta) in &state.entries {
            append_path_to_tar(&mut builder, root, rel, meta)?;
        }
        builder.finish()?;
    }
    Ok(compress(tar_out, gz_out)?)
}

fn append_path_to_tar<W: Write>(
    builder: &mut tar::Builder<W>,
    root: &Path,
    rel: &str,
    meta: &EntryMeta,
) -> Result<(), Error> {
    let full = root.join(rel);
    let mut header = tar::Header::new_gnu();
    header.set_mode(meta.mode);
    header.set_uid(meta.uid);
    header.set_gid(meta.gid);
    header.set_mtime(0);
    match meta.kind {
        EntryKind::Dir => {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_cksum();
            let dir_name = if rel.ends_with('/') {
                rel.to_owned()
            } else {
                format!("{rel}/")
            };
            builder.append_data(&mut header, &dir_name, std::io::empty())?;
        }
        EntryKind::Symlink => {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            builder.append_link(&mut header, rel, &meta.digest_or_link)?;
        }
        EntryKind::File => {
            let f = File::open(&full)?;
            let len = f.metadata()?.len();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(len);
            header.set_cksum();
            builder.append_data(&mut header, rel, BufReader::new(f))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_layer_creates_and_applies_whiteouts_and_changes() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(root.join("usr/local/bin")).unwrap();
        std::fs::write(root.join("etc/old.conf"), "old").unwrap();
        std::fs::write(root.join("etc/keep.conf"), "keep").unwrap();

        let before = TreeState::capture(&root).unwrap();

        // Modify root: remove etc/old.conf, add usr/local/bin/app
        std::fs::remove_file(root.join("etc/old.conf")).unwrap();
        std::fs::write(root.join("usr/local/bin/app"), "#!/bin/sh\necho hi\n").unwrap();

        let tar_out = t.path().join("layer.tar");
        let gz_out = t.path().join("layer.tar.gz");
        let art = create_diff_layer(&before, &root, &tar_out, &gz_out)
            .unwrap()
            .0
            .expect("changes present");

        // Verify decompression matches diff_id
        let check_tar = t.path().join("check.tar");
        decompress(&gz_out, &art.diff_id, &check_tar).unwrap();

        // Apply to a fresh copy of the base tree
        let target = t.path().join("target");
        std::fs::create_dir_all(target.join("etc")).unwrap();
        std::fs::write(target.join("etc/old.conf"), "old").unwrap();
        std::fs::write(target.join("etc/keep.conf"), "keep").unwrap();
        apply(&check_tar, &target).unwrap();

        assert!(!target.join("etc/old.conf").exists());
        assert_eq!(
            std::fs::read_to_string(target.join("etc/keep.conf")).unwrap(),
            "keep"
        );
        assert_eq!(
            std::fs::read_to_string(target.join("usr/local/bin/app")).unwrap(),
            "#!/bin/sh\necho hi\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn capture_from_rehashes_a_rewrite_of_the_same_size() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("f"), "aaaa").unwrap();
        std::fs::write(t.path().join("g"), "keep").unwrap();
        // Past the racy window, so the stamps are kept.
        std::thread::sleep(std::time::Duration::from_millis(2100));
        let first = TreeState::capture(t.path()).unwrap();
        assert!(first.stamps.contains_key("f"));

        std::fs::write(t.path().join("f"), "bbbb").unwrap();
        let second = TreeState::capture_from(t.path(), Some(&first)).unwrap();
        let fresh = TreeState::capture(t.path()).unwrap();
        assert_ne!(second.entries["f"], first.entries["f"]);
        assert_eq!(second.entries, fresh.entries);
        // The rewritten file is racy now; the untouched one keeps its stamp.
        assert!(!second.stamps.contains_key("f"));
        assert!(second.stamps.contains_key("g"));
    }
}
