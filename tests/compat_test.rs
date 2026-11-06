//! jailer against BuildKit and Buildah: each case in tests/compat/cases, built
//! by jailer, gives the config and files `scripts/compat-reference.py` recorded
//! for each, but for the differences tests/compat/differences.TOOL names.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use jailer::build::{BuildBackend, BuildOptions, build};
use jailer::registry::{Client, sha256};
use jailer::runtime::{Config, JailRuntime};
use jailer::store::Store;
use jailer::sys::FakeSys;
use serde_json::{Value, json};

const KEYS: [&str; 12] = [
    "Cmd",
    "Entrypoint",
    "Env",
    "ExposedPorts",
    "Labels",
    "OnBuild",
    "Shell",
    "StopSignal",
    "User",
    "Volumes",
    "WorkingDir",
    "Healthcheck",
];

fn compat() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/compat")
}

/// `mode` of a file, or `-` where the file system has none to compare.
fn mode(meta: &std::fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        format!("{:o}", meta.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        "-".to_owned()
    }
}

/// The files under `root`, as the reference records them.
fn files(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(dir) = todo.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let meta = std::fs::symlink_metadata(&path).unwrap();
            let line = if meta.is_dir() {
                todo.push(path);
                format!("dir {}", mode(&meta))
            } else if meta.is_symlink() {
                format!("link {}", std::fs::read_link(&path).unwrap().display())
            } else {
                let digest = sha256(&std::fs::read(&path).unwrap());
                let hex = digest.strip_prefix("sha256:").unwrap_or(&digest).to_owned();
                format!("file {} {hex}", mode(&meta))
            };
            out.insert(rel, line);
        }
    }
    out
}

/// What the case gives: its config and files, or the build's error.
async fn built(case: &Path, tmp: &Path, jobs: usize) -> Result<Value, String> {
    let sys = Arc::new(FakeSys::new());
    let store: Arc<Store> = Arc::new(
        jailer::store::open(
            sys.clone(),
            None,
            &tmp.join("store"),
            Client::new().unwrap(),
        )
        .unwrap(),
    );
    let runtime = JailRuntime::new(
        sys,
        store.clone(),
        Config {
            state_dir: tmp.join("containers"),
            dataset: None,
            shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
            prune_images: false,
        },
    )
    .unwrap();
    let opts = BuildOptions {
        context_dir: case.join("ctx"),
        containerfile: Some(case.join("Containerfile")),
        tag: "localhost/compat:1".to_owned(),
        build_args: BTreeMap::new(),
        target: std::fs::read_to_string(case.join("target"))
            .ok()
            .map(|t| t.trim().to_owned()),
        jobs,
        backend: BuildBackend::Native,
        creds: Default::default(),
        strict_lint: false,
        no_cache: true,
        squash: false,
        cache_max: None,
        secrets: BTreeMap::new(),
        ssh: BTreeMap::new(),
        jail_params: Vec::new(),
        labels: BTreeMap::new(),
        timestamp: None,
        limits: Default::default(),
        compression: Default::default(),
        cpuset: None,
        annotations: BTreeMap::new(),
        cache_from: Vec::new(),
        cache_to: None,
    };
    let result = build(&store, &runtime, &opts)
        .await
        .map_err(|e| e.to_string())?;
    let root = tmp.join("root");
    store.prepare_rootfs(&result.image, &root, None).unwrap();
    let config = serde_json::to_value(&result.image.config).unwrap();
    let kept: serde_json::Map<String, Value> = KEYS
        .iter()
        .filter_map(|k| {
            let v = config["config"].get(*k)?;
            let empty = match v {
                Value::Null => true,
                Value::String(s) => s.is_empty(),
                Value::Array(a) => a.is_empty(),
                Value::Object(o) => o.is_empty(),
                _ => false,
            };
            (!empty).then(|| ((*k).to_owned(), v.clone()))
        })
        .collect();
    let mut image = json!({ "config": kept, "files": files(&root) });
    if let Some(author) = config.get("author").filter(|a| a.as_str() != Some("")) {
        image["author"] = author.clone();
    }
    Ok(image)
}

/// What BuildKit gives every image from scratch, for Linux, and jailer does
/// not: Linux's `PATH`, and `/` as the working directory, which is the default.
fn without_linux_defaults(image: &mut Value) {
    let config = image["config"].as_object_mut().unwrap();
    if let Some(env) = config.get_mut("Env").and_then(Value::as_array_mut) {
        env.retain(|e| e != "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        if env.is_empty() {
            config.remove("Env");
        }
    }
    if config.get("WorkingDir").is_some_and(|w| w == "/") {
        config.remove("WorkingDir");
    }
    // Buildah's mark on every image it makes.
    if let Some(labels) = config.get_mut("Labels").and_then(Value::as_object_mut) {
        labels.remove("io.buildah.version");
        if labels.is_empty() {
            config.remove("Labels");
        }
    }
}

/// What differs between `want` and `got`, as `case path: want != got`.
fn differences(case: &str, path: &str, want: &Value, got: &Value, out: &mut Vec<String>) {
    match (want, got) {
        (Value::Object(w), Value::Object(g)) => {
            let keys: std::collections::BTreeSet<&String> = w.keys().chain(g.keys()).collect();
            for k in keys {
                let (a, b) = (w.get(k), g.get(k));
                let null = Value::Null;
                differences(
                    case,
                    &format!("{path}/{k}"),
                    a.unwrap_or(&null),
                    b.unwrap_or(&null),
                    out,
                );
            }
        }
        (Value::String(w), Value::String(g)) if !cfg!(unix) && path.contains("/files/") => {
            // No modes to compare here: what kind of file, and its contents.
            let parts = |s: &str| {
                let p: Vec<String> = s.split(' ').map(str::to_owned).collect();
                (p[0].clone(), p.last().cloned())
            };
            let same = if w.starts_with("dir") {
                g.starts_with("dir")
            } else {
                parts(w) == parts(g)
            };
            if !same {
                out.push(format!("{case} {path}: {want} != {got}"));
            }
        }
        _ if want != got => out.push(format!("{case} {path}: {want} != {got}")),
        _ => {}
    }
}

/// Every way jailer's builds differ from `tool`'s records, given what jailer
/// made of each case.
fn compare(tool: &str, made: &BTreeMap<String, Result<Value, String>>) -> Vec<String> {
    let expected = compat().join("expected").join(tool);
    let mut found = Vec::new();
    for (name, got) in made {
        let Ok(text) = std::fs::read_to_string(expected.join(format!("{name}.json"))) else {
            assert!(expected.join(format!("{name}.error")).exists(), "{name}");
            if let Ok(got) = got {
                found.push(format!(
                    "{name} /build: {tool} refuses it, jailer gives {got}"
                ));
            }
            continue;
        };
        let mut want: Value = serde_json::from_str(&text).unwrap();
        without_linux_defaults(&mut want);
        match got {
            Ok(got) => differences(name, "", &want, got, &mut found),
            Err(e) => found.push(format!("{name} /build: {tool} builds it, jailer: {e}")),
        }
    }
    found
}

/// Fails on a difference `differences.TOOL` does not name, or names in vain.
fn check(tool: &str, found: &[String]) -> Result<(), String> {
    let known = std::fs::read_to_string(compat().join(format!("differences.{tool}"))).unwrap();
    let known: Vec<(&str, &str)> = known
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut words = l.split_whitespace();
            (words.next().unwrap(), words.next().unwrap())
        })
        .collect();
    let matches = |case: &str, path: &str, line: &str| {
        line.starts_with(&format!("{case} {path}:")) || line.starts_with(&format!("{case} {path}/"))
    };
    let unknown: Vec<&str> = found
        .iter()
        .filter(|l| !known.iter().any(|(c, p)| matches(c, p, l)))
        .map(String::as_str)
        .collect();
    let stale: Vec<&(&str, &str)> = known
        .iter()
        .filter(|(c, p)| !found.iter().any(|l| matches(c, p, l)))
        .collect();
    if unknown.is_empty() && stale.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{tool}: differences not named:\n{}\nnamed but gone: {stale:?}\n",
        unknown.join("\n")
    ))
}

#[tokio::test]
async fn containerfiles_build_as_they_do_with_the_reference_builders() {
    let mut names: Vec<String> = std::fs::read_dir(compat().join("cases"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert!(!names.is_empty());
    let mut made = BTreeMap::new();
    for name in names {
        let tmp = tempfile::tempdir().unwrap();
        let case = compat().join("cases").join(&name);
        let one = built(&case, tmp.path(), 1).await;
        // Stages at once give what they give one at a time.
        let tmp = tempfile::tempdir().unwrap();
        let many = built(&case, tmp.path(), 4).await;
        assert_eq!(one.as_ref().ok(), many.as_ref().ok(), "{name}");
        made.insert(name, one);
    }
    let failures: Vec<String> = ["buildkit", "buildah"]
        .iter()
        .filter_map(|tool| check(tool, &compare(tool, &made)).err())
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
