//! Applying and creating OCI image layers: decompression with `diff_id`
//! verification, whiteout handling (`.wh.`), extraction with `bsdtar`
//! preserving FreeBSD file flags, and filesystem diffing to produce new
//! OCI tar+gzip layers during `jailer build`.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::Error;

const WHITEOUT: &str = ".wh.";
const OPAQUE: &str = ".wh..wh..opq";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerArtifact {
    /// Uncompressed tar digest (`sha256:...`), recorded in `rootfs.diff_ids`.
    pub diff_id: String,
    /// Compressed gzip blob digest (`sha256:...`), recorded in the manifest.
    pub blob_digest: String,
    /// Size of the compressed gzip blob in bytes.
    pub blob_size: u64,
}

/// Decompresses `blob` (gzip, zstd or plain tar, told by its first bytes)
/// into `tar`, checking the result against `diff_id`.
pub fn decompress(blob: &Path, diff_id: &str, tar: &Path) -> Result<(), Error> {
    let mut input = BufReader::new(File::open(blob)?);
    let mut magic = [0u8; 4];
    let n = read_full(&mut input, &mut magic)?;
    let head = std::io::Cursor::new(magic[..n].to_vec()).chain(input);
    let mut reader: Box<dyn Read> = match magic {
        [0x1f, 0x8b, ..] => Box::new(flate2::read::MultiGzDecoder::new(head)),
        [0x28, 0xb5, 0x2f, 0xfd] => Box::new(
            ruzstd::decoding::StreamingDecoder::new(head)
                .map_err(|e| Error::Unsupported(format!("a zstd layer: {e}")))?,
        ),
        _ => Box::new(head),
    };
    let mut out = BufWriter::new(File::create(tar)?);
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        out.write_all(&buf[..n])?;
    }
    out.flush()?;
    let got = format!("sha256:{:x}", hash.finalize());
    if !diff_id.is_empty() && got != diff_id {
        return Err(Error::Digest {
            what: "layer contents (diff_id)".to_owned(),
            expected: diff_id.to_owned(),
            got,
        });
    }
    Ok(())
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            m => n += m,
        }
    }
    Ok(n)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Whiteout {
    /// A path lower layers made, to remove.
    Remove(PathBuf),
    /// A directory whose lower contents are hidden: emptied.
    Opaque(PathBuf),
}

/// The whiteouts in an uncompressed layer.
pub fn whiteouts(tar: &Path) -> Result<Vec<Whiteout>, Error> {
    let mut archive = tar::Archive::new(BufReader::new(File::open(tar)?));
    let mut out = Vec::new();
    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.path()?.into_owned();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        if name == OPAQUE {
            out.push(Whiteout::Opaque(dir));
        } else if let Some(hidden) = name.strip_prefix(WHITEOUT) {
            out.push(Whiteout::Remove(dir.join(hidden)));
        }
    }
    Ok(out)
}

/// `rel` under `root`, or `None` if it reaches outside it or through a
/// symlink (which a lower layer's directory cannot be, so there is nothing
/// of it to remove).
fn inside(root: &Path, rel: &Path) -> Result<Option<PathBuf>, Error> {
    let mut path = root.to_path_buf();
    let mut parts = rel
        .components()
        .filter(|c| *c != Component::CurDir)
        .peekable();
    while let Some(c) = parts.next() {
        let Component::Normal(name) = c else {
            return Err(Error::Unsupported(format!(
                "a whiteout outside the image: {}",
                rel.display()
            )));
        };
        path.push(name);
        if parts.peek().is_some() {
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => {}
                _ => return Ok(None),
            }
        }
    }
    Ok(Some(path))
}

/// Applies whiteouts to `root`, a lower layer's clone.
pub fn apply_whiteouts(root: &Path, whiteouts: &[Whiteout]) -> Result<(), Error> {
    for w in whiteouts {
        match w {
            Whiteout::Remove(rel) => {
                if let Some(p) = inside(root, rel)? {
                    remove_tree(&p)?;
                }
            }
            Whiteout::Opaque(rel) => {
                let Some(dir) = inside(root, rel)? else {
                    continue;
                };
                match std::fs::symlink_metadata(&dir) {
                    Ok(m) if m.is_dir() => {
                        for e in std::fs::read_dir(&dir)? {
                            remove_tree(&e?.path())?;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

/// Removes a file, link or directory tree without following links,
/// clearing file flags (`schg` and the like) that would refuse it.
pub fn remove_tree(path: &Path) -> Result<(), Error> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    clear_flags(path)?;
    if meta.is_dir() {
        for e in std::fs::read_dir(path)? {
            remove_tree(&e?.path())?;
        }
        std::fs::remove_dir(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(target_os = "freebsd")]
pub fn clear_flags(path: &Path) -> Result<(), Error> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::Unsupported(format!("a NUL in {}", path.display())))?;
    // SAFETY: `c` is a valid NUL-terminated path; lchflags does not follow
    // a final symlink.
    if unsafe { libc::lchflags(c.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(target_os = "freebsd"))]
pub fn clear_flags(_: &Path) -> Result<(), Error> {
    Ok(())
}

/// Extracts an uncompressed layer into `root`, leaving out whiteout files.
pub fn extract(tar: &Path, root: &Path) -> Result<(), Error> {
    let mut cmd = Command::new("tar");
    cmd.arg("-x");
    if cfg!(target_os = "freebsd") {
        // Owners as numbers (the image's, not this host's names), modes,
        // file flags, extended attributes; and flags cleared on files a
        // layer replaces.
        cmd.args([
            "-p",
            "--numeric-owner",
            "--fflags",
            "--xattrs",
            "--clear-nochange-fflags",
        ]);
    }
    cmd.arg("-f")
        .arg(tar)
        .arg("-C")
        .arg(root)
        .args(["--exclude", ".wh.*", "--exclude", "*/.wh.*"]);
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(Error::Extract(
            String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        ));
    }
    Ok(())
}

/// Applies an uncompressed layer to `root`.
pub fn apply(tar: &Path, root: &Path) -> Result<(), Error> {
    apply_whiteouts(root, &whiteouts(tar)?)?;
    extract(tar, root)
}

/// Copies a rootfs directory tree `src` to `dst`, preserving symlinks,
/// permissions, numeric ownership, and (on FreeBSD) file flags.
pub fn copy_tree(src: &Path, dst: &Path) -> Result<(), Error> {
    std::fs::create_dir_all(dst)?;
    if cfg!(unix) {
        let tmp = tempfile::NamedTempFile::new()?;
        let mut pack = Command::new("tar");
        if cfg!(target_os = "freebsd") {
            pack.args(["--numeric-owner", "--fflags", "--xattrs"]);
        }
        let out = pack
            .arg("-cf")
            .arg(tmp.path())
            .arg("-C")
            .arg(src)
            .arg(".")
            .output()?;
        if !out.status.success() {
            return Err(Error::Extract(format!(
                "archiving {}: {}",
                src.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        extract(tmp.path(), dst)?;
        return Ok(());
    }
    copy_dir_recursive(src, dst)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), Error> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let target = dst.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            let link = std::fs::read_link(&path)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(link, &target)?;
            #[cfg(windows)]
            {
                if path.is_dir() {
                    std::os::windows::fs::symlink_dir(link, &target)?;
                } else {
                    std::os::windows::fs::symlink_file(link, &target)?;
                }
            }
        } else if meta.is_dir() {
            copy_dir_recursive(&path, &target)?;
        } else {
            std::fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

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
}

impl TreeState {
    /// Captures the state of all files, directories, and symlinks under `root`.
    pub fn capture(root: &Path) -> Result<Self, Error> {
        let mut entries = BTreeMap::new();
        if root.exists() {
            walk_capture(root, root, &mut entries)?;
        }
        Ok(Self { entries })
    }
}

fn walk_capture(
    root: &Path,
    dir: &Path,
    out: &mut BTreeMap<String, EntryMeta>,
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
            out.insert(
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
            out.insert(
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
            walk_capture(root, &full, out)?;
        } else if meta.is_file() {
            let digest = file_sha256(&full)?;
            out.insert(
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
/// blob to `gz_out`, and returns the layer digests (`None` if nothing changed).
pub fn create_diff_layer(
    before: &TreeState,
    after_root: &Path,
    tar_out: &Path,
    gz_out: &Path,
) -> Result<Option<LayerArtifact>, Error> {
    let after = TreeState::capture(after_root)?;
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
        return Ok(None);
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

    compress_and_hash_tar(tar_out, gz_out).map(Some)
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
    compress_and_hash_tar(tar_out, gz_out)
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

pub fn compress_and_hash_tar(tar_path: &Path, gz_path: &Path) -> Result<LayerArtifact, Error> {
    let mut tar_in = BufReader::new(File::open(tar_path)?);
    let gz_file = BufWriter::new(File::create(gz_path)?);
    let mut gz_enc = flate2::write::GzEncoder::new(gz_file, flate2::Compression::default());
    let mut diff_hash = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = tar_in.read(&mut buf)?;
        if n == 0 {
            break;
        }
        diff_hash.update(&buf[..n]);
        gz_enc.write_all(&buf[..n])?;
    }
    let mut gz_file = gz_enc.finish()?;
    gz_file.flush()?;
    drop(gz_file);

    let diff_id = format!("sha256:{:x}", diff_hash.finalize());
    let mut gz_in = BufReader::new(File::open(gz_path)?);
    let mut blob_hash = Sha256::new();
    let mut blob_size = 0u64;
    loop {
        let n = gz_in.read(&mut buf)?;
        if n == 0 {
            break;
        }
        blob_hash.update(&buf[..n]);
        blob_size += n as u64;
    }
    let blob_digest = format!("sha256:{:x}", blob_hash.finalize());
    Ok(LayerArtifact {
        diff_id,
        blob_digest,
        blob_size,
    })
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
}
