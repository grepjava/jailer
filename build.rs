//! Names the Legion crates jailer is built with in `jailer --version`, as
//! Cargo.lock has them: "0.5.4 (legion v0.1.17 7df630d)", or the commit
//! alone for a pin by revision.

use std::path::Path;

fn main() {
    let lock = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("Cargo.lock");
    println!("cargo::rerun-if-changed={}", lock.display());
    let legion = std::fs::read_to_string(&lock)
        .ok()
        .and_then(|text| legion(&text))
        .unwrap_or_else(|| "unknown".to_owned());
    println!(
        "cargo::rustc-env=JAILER_VERSION={} (legion {legion})",
        std::env::var("CARGO_PKG_VERSION").unwrap()
    );
}

/// legion-image's source in a Cargo.lock: its tag and short commit, the
/// commit alone, or "path" when built from a local checkout.
fn legion(lock: &str) -> Option<String> {
    let entry = lock
        .split("[[package]]")
        .find(|p| p.lines().any(|l| l.trim() == "name = \"legion-image\""))?;
    let Some(source) = entry
        .lines()
        .find_map(|l| l.trim().strip_prefix("source = \""))
    else {
        return Some("path".to_owned());
    };
    let source = source.trim_end_matches('"');
    let (query, commit) = source.rsplit_once('#')?;
    let commit = &commit[..commit.len().min(7)];
    let tag = query
        .split_once('?')
        .and_then(|(_, q)| q.split('&').find_map(|kv| kv.strip_prefix("tag=")));
    Some(match tag {
        Some(tag) => format!("{tag} {commit}"),
        None => commit.to_owned(),
    })
}
