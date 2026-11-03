//! Creating OCI image layers during `jailer build`: snapshots of a root
//! file system, compared to write what a step changed (and `.wh.`
//! whiteouts for what it removed) as a deterministic tar. Applying layers,
//! and copying and removing trees with their file flags, is
//! `legion_image::layer`'s, re-exported here.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Component, Path};

use sha2::{Digest, Sha256};

use crate::Error;

/// How a built layer's blob is compressed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Compression {
    #[default]
    Gzip,
    Zstd,
}

pub const OCI_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

impl Compression {
    pub fn media_type(self) -> &'static str {
        match self {
            Compression::Gzip => legion_image::oci::OCI_LAYER_GZIP,
            Compression::Zstd => OCI_LAYER_ZSTD,
        }
    }

    /// Compresses the tar `tar` into `out`, returning both digests.
    pub fn compress(self, tar: &Path, out: &Path) -> Result<LayerArtifact, Error> {
        if self == Compression::Gzip {
            return Ok(compress(tar, out)?);
        }
        let mut input = std::io::BufReader::new(std::fs::File::open(tar)?);
        let mut enc = zstd::stream::Encoder::new(
            std::io::BufWriter::new(std::fs::File::create(out)?),
            zstd::DEFAULT_COMPRESSION_LEVEL,
        )?;
        let mut diff = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = std::io::Read::read(&mut input, &mut buf)?;
            if n == 0 {
                break;
            }
            diff.update(&buf[..n]);
            enc.write_all(&buf[..n])?;
        }
        enc.finish()?.flush()?;
        let mut blob = Sha256::new();
        let mut size = 0u64;
        let mut input = std::fs::File::open(out)?;
        loop {
            let n = std::io::Read::read(&mut input, &mut buf)?;
            if n == 0 {
                break;
            }
            blob.update(&buf[..n]);
            size += n as u64;
        }
        Ok(LayerArtifact {
            diff_id: format!("sha256:{:x}", diff.finalize()),
            blob_digest: format!("sha256:{:x}", blob.finalize()),
            blob_size: size,
        })
    }
}

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
    /// FreeBSD file flags that matter in an image ([`FLAGS`]).
    pub flags: u32,
}

/// File flags kept in layers, by chflags(1)'s names: what bsdtar
/// `--fflags` restores. Others (`uarch`, which ZFS sets on writes) are
/// left out.
const FLAGS: [(u32, &str); 7] = [
    (0x0000_0001, "nodump"),
    (0x0000_0002, "uchg"),
    (0x0000_0004, "uappnd"),
    (0x0000_0010, "uunlnk"),
    (0x0002_0000, "schg"),
    (0x0004_0000, "sappnd"),
    (0x0010_0000, "sunlnk"),
];

/// `flags` as bsdtar's `SCHILY.fflags` names them.
fn flags_text(flags: u32) -> String {
    FLAGS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(target_os = "freebsd")]
pub fn file_flags(meta: &std::fs::Metadata) -> u32 {
    use std::os::freebsd::fs::MetadataExt;
    FLAGS
        .iter()
        .fold(0, |kept, (bit, _)| kept | (meta.st_flags() & bit))
}

#[cfg(not(target_os = "freebsd"))]
pub fn file_flags(_: &std::fs::Metadata) -> u32 {
    0
}

/// Sets `path`'s file flags (not following a link).
#[cfg(target_os = "freebsd")]
pub fn set_flags(path: &Path, flags: u32) -> Result<(), Error> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::Build(format!("a NUL in {}", path.display())))?;
    // SAFETY: `c` is a valid NUL-terminated path.
    if unsafe { libc::lchflags(c.as_ptr(), flags.into()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(target_os = "freebsd"))]
pub fn set_flags(_: &Path, _: u32) -> Result<(), Error> {
    Ok(())
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
    /// Hard-linked files: each name of one, and the first of its names,
    /// which layers hold as the file (the others link to it).
    links: BTreeMap<String, String>,
}

impl TreeState {
    /// Where `rel` links to, if it is a second name of a file.
    fn link_of(&self, rel: &str) -> Option<&str> {
        self.links
            .get(rel)
            .map(String::as_str)
            .filter(|first| *first != rel)
    }

    /// `paths` with every other name of the files among them, so that a
    /// layer holds each hard-linked file with all its names: a link to a
    /// file a lower layer has would need that file's flags to allow it.
    fn with_link_groups(&self, paths: Vec<String>) -> BTreeSet<String> {
        let firsts: BTreeSet<&String> = paths.iter().filter_map(|p| self.links.get(p)).collect();
        let mut all: BTreeSet<String> = paths.iter().cloned().collect();
        all.extend(
            self.links
                .iter()
                .filter(|(_, first)| firsts.contains(first))
                .map(|(p, _)| p.clone()),
        );
        all
    }
}

/// Names of hard-linked files by device and inode.
type Inodes = HashMap<(u64, u64), Vec<String>>;

/// A hard-linked file's device and inode.
#[cfg(unix)]
pub fn inode(meta: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    (meta.nlink() > 1).then(|| (meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
pub fn inode(_: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
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
        let mut inodes = Inodes::new();
        if root.exists() {
            walk_capture(root, root, prev, racy_after, &mut state, &mut inodes)?;
        }
        for names in inodes.into_values().filter(|n| n.len() > 1) {
            let first = names.iter().min().expect("names").clone();
            state
                .links
                .extend(names.into_iter().map(|n| (n, first.clone())));
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
    inodes: &mut Inodes,
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
        let flags = file_flags(&meta);
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
                    flags,
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
                    flags,
                },
            );
            walk_capture(root, &full, prev, racy_after, out, inodes)?;
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
            if let Some(key) = inode(&meta) {
                inodes.entry(key).or_default().push(rel_str.clone());
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
                    flags,
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
    compression: Compression,
) -> Result<(Option<LayerArtifact>, TreeState), Error> {
    let after = TreeState::capture_from(after_root, Some(before))?;
    let mut deleted: Vec<String> = Vec::new();
    for old_path in before.entries.keys() {
        if !after.entries.contains_key(old_path) {
            // Only emit a whiteout if its parent directory was not also
            // deleted. One whose parent is now a file or a link is kept:
            // it empties the directory before the layer replaces it.
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
        // A file linked to another, or no longer linked, has changed even
        // if its contents have not.
        if before.entries.get(path) != Some(meta) || before.links.get(path) != after.links.get(path)
        {
            changed.push(path.clone());
        }
    }
    let changed = after.with_link_groups(changed);

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
                append_path_to_tar(&mut builder, after_root, dir_rel, meta, None)?;
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
            append_path_to_tar(
                &mut builder,
                after_root,
                ch_rel,
                meta,
                after.link_of(ch_rel),
            )?;
        }

        builder.finish()?;
    }

    let art = compression.compress(tar_out, gz_out)?;
    Ok((Some(art), after))
}

/// Packs an entire root directory `root` into an OCI layer (`tar_out` and
/// `gz_out`), returning its `diff_id` and compressed `blob_digest`.
pub fn pack_directory_layer(
    root: &Path,
    tar_out: &Path,
    gz_out: &Path,
    compression: Compression,
) -> Result<LayerArtifact, Error> {
    let state = TreeState::capture(root)?;
    {
        let tar_file = BufWriter::new(File::create(tar_out)?);
        let mut builder = tar::Builder::new(tar_file);
        builder.follow_symlinks(false);
        for (rel, meta) in &state.entries {
            append_path_to_tar(&mut builder, root, rel, meta, state.link_of(rel))?;
        }
        builder.finish()?;
    }
    compression.compress(tar_out, gz_out)
}

fn append_path_to_tar<W: Write>(
    builder: &mut tar::Builder<W>,
    root: &Path,
    rel: &str,
    meta: &EntryMeta,
    link_to: Option<&str>,
) -> Result<(), Error> {
    let full = root.join(rel);
    let mut header = tar::Header::new_gnu();
    if let Some(first) = link_to {
        // Written after `first`: entries go in path order, and it is the
        // least of the file's names.
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        builder.append_link(&mut header, rel, first)?;
        return Ok(());
    }
    if meta.flags != 0 {
        let text = flags_text(meta.flags);
        builder.append_pax_extensions([("SCHILY.fflags", text.as_bytes())])?;
    }
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
        let art = create_diff_layer(&before, &root, &tar_out, &gz_out, Compression::Gzip)
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

        // A directory replaced by a file: whiteouts below it come first, so
        // that an extractor going in order empties it before the file.
        let before = TreeState::capture(&root).unwrap();
        remove_tree(&root.join("etc")).unwrap();
        std::fs::write(root.join("etc"), "now a file").unwrap();
        create_diff_layer(&before, &root, &tar_out, &gz_out, Compression::Gzip).unwrap();
        let mut archive = tar::Archive::new(File::open(&tar_out).unwrap());
        let names: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["etc/.wh.keep.conf", "etc"]);
        apply(&tar_out, &target).unwrap();
        assert_eq!(
            std::fs::read_to_string(target.join("etc")).unwrap(),
            "now a file"
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

    /// Each entry of the layer `tar`: its path, type, link target and
    /// `SCHILY.fflags`.
    #[cfg(unix)]
    fn entries(tar: &Path) -> Vec<(String, tar::EntryType, String, String)> {
        let mut archive = tar::Archive::new(File::open(tar).unwrap());
        let mut out = Vec::new();
        for e in archive.entries().unwrap() {
            let mut e = e.unwrap();
            let flags = e
                .pax_extensions()
                .unwrap()
                .into_iter()
                .flatten()
                .map(|x| x.unwrap())
                .find(|x| x.key() == Ok("SCHILY.fflags"))
                .map(|x| x.value().unwrap().to_owned())
                .unwrap_or_default();
            let link = e
                .link_name()
                .unwrap()
                .map(|l| l.to_string_lossy().into_owned())
                .unwrap_or_default();
            let path = e.path().unwrap().to_string_lossy().into_owned();
            out.push((path, e.header().entry_type(), link, flags));
        }
        out
    }

    #[cfg(unix)]
    #[test]
    fn hard_links_go_into_layers_with_all_their_names() {
        use tar::EntryType::{Link, Regular};
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/chpass"), "chpass").unwrap();
        std::fs::hard_link(root.join("bin/chpass"), root.join("bin/chfn")).unwrap();
        std::fs::write(root.join("bin/other"), "other").unwrap();
        let tar_out = t.path().join("l.tar");
        let gz_out = t.path().join("l.tar.gz");

        pack_directory_layer(&root, &tar_out, &gz_out, Compression::Gzip).unwrap();
        let all = entries(&tar_out);
        let chfn = all.iter().find(|e| e.0 == "bin/chfn").unwrap();
        let chpass = all.iter().position(|e| e.0 == "bin/chpass").unwrap();
        assert_eq!(
            (chfn.1, chfn.2.as_str()),
            (Regular, ""),
            "the least name is the file"
        );
        assert_eq!(all[chpass].1, Link);
        assert_eq!(all[chpass].2, "bin/chfn");

        // A third name brings the others along.
        let before = TreeState::capture(&root).unwrap();
        std::fs::hard_link(root.join("bin/chpass"), root.join("bin/chsh")).unwrap();
        let (_, after) =
            create_diff_layer(&before, &root, &tar_out, &gz_out, Compression::Gzip).unwrap();
        let names: Vec<_> = entries(&tar_out)
            .into_iter()
            .filter(|e| e.0.starts_with("bin/c"))
            .map(|e| (e.0, e.1, e.2))
            .collect();
        assert_eq!(
            names,
            [
                ("bin/chfn".to_owned(), Regular, String::new()),
                ("bin/chpass".to_owned(), Link, "bin/chfn".to_owned()),
                ("bin/chsh".to_owned(), Link, "bin/chfn".to_owned()),
            ]
        );
        assert!(after.link_of("bin/other").is_none());

        // Applied, they are one file again.
        let target = t.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        apply(&tar_out, &target).unwrap();
        use std::os::unix::fs::MetadataExt;
        let ino = |p: &str| std::fs::metadata(target.join(p)).unwrap().ino();
        assert_eq!(ino("bin/chfn"), ino("bin/chsh"));
        assert_eq!(ino("bin/chfn"), ino("bin/chpass"));
    }

    #[cfg(unix)]
    #[test]
    fn linking_or_unlinking_alike_files_is_a_change() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a"), "same").unwrap();
        std::fs::write(root.join("b"), "same").unwrap();
        let tar_out = t.path().join("l.tar");
        let gz_out = t.path().join("l.tar.gz");
        let diff = |before: &TreeState| {
            create_diff_layer(before, &root, &tar_out, &gz_out, Compression::Gzip).unwrap()
        };

        let before = TreeState::capture(&root).unwrap();
        std::fs::remove_file(root.join("b")).unwrap();
        std::fs::hard_link(root.join("a"), root.join("b")).unwrap();
        let (layer, linked) = diff(&before);
        assert!(layer.is_some(), "linking is a change");

        std::fs::remove_file(root.join("b")).unwrap();
        std::fs::write(root.join("b"), "same").unwrap();
        let (layer, _) = diff(&linked);
        assert!(layer.is_some(), "unlinking is a change");
    }

    #[test]
    fn flags_are_named_as_bsdtar_names_them() {
        assert_eq!(flags_text(0x0002_0000), "schg");
        assert_eq!(flags_text(0x0000_0001 | 0x0000_0002), "nodump,uchg");
        assert_eq!(flags_text(0), "");
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn file_flags_go_into_layers() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("f"), "f").unwrap();
        let before = TreeState::capture(&root).unwrap();
        let chflags = |flags: &str| {
            let ok = std::process::Command::new("chflags")
                .args([flags, root.join("f").to_str().unwrap()])
                .status()
                .unwrap()
                .success();
            assert!(ok);
        };
        // A change of flags alone is a change. (On ZFS a user may set only
        // nodump; ZFS sets uarch itself, which layers leave out.)
        chflags("nodump");
        let tar_out = t.path().join("l.tar");
        let gz_out = t.path().join("l.tar.gz");
        let made = create_diff_layer(&before, &root, &tar_out, &gz_out, Compression::Gzip);
        chflags("0");
        assert!(made.unwrap().0.is_some());
        let f = entries(&tar_out).into_iter().find(|e| e.0 == "f").unwrap();
        assert_eq!(f.3, "nodump");
    }
}
