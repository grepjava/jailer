use std::collections::BTreeMap;
use std::convert::Infallible;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use jailer::Reference;
use jailer::build::{BuildBackend, BuildOptions, build};
use jailer::init::{InitOptions, Template, scaffold};
use jailer::registry::{Client, Credentials, sha256};
use jailer::runtime::{Config, JailRuntime};
use jailer::sys::FakeSys;

#[derive(Default)]
struct MockRegistry {
    blobs: Mutex<BTreeMap<String, Vec<u8>>>,
    manifests: Mutex<BTreeMap<String, (String, Vec<u8>)>>,
}

async fn start_mock_registry() -> (SocketAddr, Arc<MockRegistry>) {
    let state = Arc::new(MockRegistry::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let st = state.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let st = st.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let st = st.clone();
                    async move { handle_registry(req, st).await }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (addr, state)
}

async fn handle_registry(
    req: Request<Incoming>,
    st: Arc<MockRegistry>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();

    // Plain files, for `ADD <url>`
    if let Some(name) = path.strip_prefix("/files/") {
        return Ok(Response::builder()
            .status(if name == "data.bin" {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            })
            .body(Full::new(Bytes::from_static(b"downloaded\n")))
            .unwrap());
    }

    // Check Bearer token flow
    if path == "/token" {
        let body = serde_json::json!({"token": "test-bearer-token"}).to_string();
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap());
    }

    let auth = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if auth != "Bearer test-bearer-token" {
        let host = req
            .headers()
            .get("Host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("127.0.0.1");
        let challenge = format!(
            "Bearer realm=\"http://{host}/token\",service=\"mock\",scope=\"repository:me/app:pull,push\""
        );
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", challenge)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    let bytes = req
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes().to_vec())
        .unwrap_or_default();

    if method == Method::HEAD && path.contains("/blobs/") {
        let digest = path.rsplit('/').next().unwrap_or("");
        let has = st.blobs.lock().unwrap().contains_key(digest);
        return Ok(Response::builder()
            .status(if has {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            })
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    if method == Method::GET && path.contains("/blobs/") {
        let digest = path.rsplit('/').next().unwrap_or("");
        if let Some(data) = st.blobs.lock().unwrap().get(digest).cloned() {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from(data)))
                .unwrap());
        }
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    if method == Method::POST && path.ends_with("/blobs/uploads/") {
        let upload_path = path.replace("/blobs/uploads/", "/blobs/uploads/u1");
        return Ok(Response::builder()
            .status(StatusCode::ACCEPTED)
            .header("Location", upload_path)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    if method == Method::PUT && path.contains("/blobs/uploads/") {
        let digest = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("digest="))
            .unwrap_or("")
            .to_owned();
        st.blobs.lock().unwrap().insert(digest, bytes);
        return Ok(Response::builder()
            .status(StatusCode::CREATED)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    if method == Method::PUT && path.contains("/manifests/") {
        let target = path.rsplit('/').next().unwrap_or("").to_owned();
        let digest = sha256(&bytes);
        let mut m = st.manifests.lock().unwrap();
        m.insert(target, (digest.clone(), bytes.clone()));
        m.insert(digest.clone(), (digest, bytes));
        return Ok(Response::builder()
            .status(StatusCode::CREATED)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    if method == Method::GET && path.contains("/manifests/") {
        let target = path.rsplit('/').next().unwrap_or("");
        if let Some((_, data)) = st.manifests.lock().unwrap().get(target).cloned() {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
                .body(Full::new(Bytes::from(data)))
                .unwrap());
        }
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

#[tokio::test]
async fn end_to_end_init_build_export_push_and_pull() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("demo");
    std::fs::create_dir_all(&project_dir).unwrap();

    // 1. Test `jailer init`
    let init_res = scaffold(&InitOptions {
        dir: project_dir.clone(),
        template: Some(Template::Runtime),
        release: Some("15.1".to_owned()),
        name: Some("demo".to_owned()),
        force: false,
    })
    .unwrap();
    assert!(init_res.containerfile.exists());

    // Create a minimal self-contained Containerfile using FROM scratch with /etc/passwd and binary
    std::fs::create_dir_all(project_dir.join("etc")).unwrap();
    std::fs::create_dir_all(project_dir.join("bin")).unwrap();
    std::fs::write(
        project_dir.join("etc/passwd"),
        "root:*:0:0:root:/root:/bin/sh\nnobody:*:65534:65534:Unprivileged:/nonexistent:/usr/sbin/nologin\n",
    )
    .unwrap();
    std::fs::write(
        project_dir.join("etc/group"),
        "wheel:*:0:root\nnobody:*:65534:\n",
    )
    .unwrap();
    let bin_path = project_dir.join("bin/demo");
    std::fs::write(&bin_path, "#!/bin/sh\necho hello\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    std::fs::write(
        project_dir.join("Containerfile"),
        r#"
FROM scratch
COPY etc/passwd /etc/passwd
COPY etc/group /etc/group
COPY --chown=nobody:nobody --chmod=0755 bin/demo /usr/local/bin/demo
ENV APP_ENV=production
WORKDIR /
USER nobody
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/demo"]
CMD ["--serve"]
"#,
    )
    .unwrap();

    let (addr, _) = start_mock_registry().await;
    let registry_host = format!("127.0.0.1:{}", addr.port());

    let sys = Arc::new(FakeSys::new());
    let client = Client::new().unwrap().plain_http(&registry_host);
    let store_dir = tmp.path().join("store1");
    let store = Arc::new(jailer::store::open(sys.clone(), None, &store_dir, client).unwrap());
    let runtime = JailRuntime::new(
        sys,
        store.clone(),
        Config {
            state_dir: tmp.path().join("containers1"),
            dataset: None,
            shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
            prune_images: false,
        },
    )
    .unwrap();

    // 2. Test `jailer build`
    let built = build(
        &store,
        &runtime,
        &BuildOptions {
            context_dir: project_dir.clone(),
            containerfile: None,
            tag: "demo:1.0".to_owned(),
            build_args: BTreeMap::new(),
            target: None,
            backend: BuildBackend::Native,
            creds: None,
            strict_lint: true,
            no_cache: false,
            squash: false,
            cache_max: None,
            secrets: BTreeMap::new(),
            ssh: BTreeMap::new(),
            jail_params: Vec::new(),
            labels: BTreeMap::new(),
            timestamp: None,
            limits: Default::default(),
        },
    )
    .await
    .unwrap();
    assert!(!built.report.has_errors(), "{:?}", built.report.findings);
    assert_eq!(built.image.references, ["localhost/demo:1.0"]);
    assert_eq!(built.image.config.config.user, "nobody");
    assert_eq!(
        built.image.config.config.entrypoint,
        ["/usr/local/bin/demo"]
    );
    assert_eq!(built.image.config.config.cmd, ["--serve"]);

    // 3. Test `jailer export` -> `app.tar` and `Store::load` into a second store
    let archive_path = tmp.path().join("demo.tar");
    store
        .export("demo:1.0", &archive_path, Some("localhost/demo:1.0"))
        .unwrap();
    assert!(archive_path.exists());
    // Docker's manifest names files the archive holds.
    let mut names = Vec::new();
    let mut docker_manifest = serde_json::Value::Null;
    for entry in tar::Archive::new(std::fs::File::open(&archive_path).unwrap())
        .entries()
        .unwrap()
    {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_string_lossy().into_owned();
        let name = name.trim_start_matches("./").to_owned();
        if name == "manifest.json" {
            docker_manifest = serde_json::from_reader(&mut entry).unwrap();
        }
        names.push(name);
    }
    let m = &docker_manifest[0];
    assert_eq!(m["RepoTags"], serde_json::json!(["localhost/demo:1.0"]));
    let layers = m["Layers"].as_array().unwrap();
    assert_eq!(layers.len(), built.image.layers.len());
    for p in layers.iter().chain([&m["Config"]]) {
        assert!(names.contains(&p.as_str().unwrap().to_owned()), "{p}");
    }

    let sys2 = Arc::new(FakeSys::new());
    let client2 = Client::new().unwrap().plain_http(&registry_host);
    let store2 =
        Arc::new(jailer::store::open(sys2, None, &tmp.path().join("store2"), client2).unwrap());
    let loaded = store2.load(&archive_path, None).await.unwrap();
    assert_eq!(loaded.id, built.image.id);
    assert_eq!(loaded.references, ["localhost/demo:1.0"]);

    // 4. Test `jailer push` to mock OCI registry and `Store::pull` into a third store
    let push_target = Reference::parse(&format!("{registry_host}/me/app:1.0")).unwrap();
    let creds = Credentials {
        username: "me".to_owned(),
        password: "secret".to_owned(),
    };
    let manifest_digest = store
        .push("demo:1.0", &push_target, Some(&creds))
        .await
        .unwrap();
    assert!(manifest_digest.starts_with("sha256:"));

    let sys3 = Arc::new(FakeSys::new());
    let client3 = Client::new().unwrap().plain_http(&registry_host);
    let store3 = Arc::new(
        jailer::store::open(
            sys3,
            Some("zroot/test-jailer/images"),
            &tmp.path().join("store3"),
            client3,
        )
        .unwrap(),
    );
    let pulled = store3
        .pull(&push_target.to_string(), Some(&creds), "me")
        .await
        .unwrap();
    assert_eq!(pulled.id, built.image.id);
    assert_eq!(pulled.digest, manifest_digest);

    // 5. Removing the last image also removes its cached blobs
    let blobs = tmp.path().join("store2/blobs/sha256");
    assert!(std::fs::read_dir(&blobs).unwrap().next().is_some());
    assert!(store2.remove("localhost/demo:1.0").await.unwrap());
    assert_eq!(std::fs::read_dir(&blobs).unwrap().count(), 0);

    // 6. A build's pin keeps what it uses through a concurrent `rmi`
    let blobs = store_dir.join("blobs/sha256");
    let pin = store.pin().unwrap();
    assert!(store.pin_image(&pin, "demo:1.0").await.unwrap().is_some());
    assert!(jailer::store::remove(&store, "demo:1.0").await.unwrap());
    assert!(std::fs::read_dir(&blobs).unwrap().next().is_some());
    drop(pin);
    assert!(!jailer::store::remove(&store, "demo:1.0").await.unwrap());
    assert_eq!(std::fs::read_dir(&blobs).unwrap().count(), 0);
}

#[tokio::test]
async fn manifest_push_publishes_one_image_per_platform() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = tmp.path().join("ctx");
    std::fs::create_dir_all(ctx.join("bin")).unwrap();
    std::fs::write(ctx.join("bin/app"), "#!/bin/sh\n").unwrap();
    std::fs::write(
        ctx.join("Containerfile"),
        "FROM scratch\nCOPY bin/app /app\nENTRYPOINT [\"/app\"]\n",
    )
    .unwrap();

    let (addr, _) = start_mock_registry().await;
    let host = format!("127.0.0.1:{}", addr.port());
    let creds = Credentials {
        username: "me".to_owned(),
        password: "secret".to_owned(),
    };
    let open = |dir: &str| {
        let sys = Arc::new(FakeSys::new());
        let client = Client::new().unwrap().plain_http(&host);
        let store = Arc::new(
            jailer::store::open(sys.clone(), None, &tmp.path().join(dir), client).unwrap(),
        );
        let runtime = JailRuntime::new(
            sys,
            store.clone(),
            Config {
                state_dir: tmp.path().join(format!("{dir}-containers")),
                dataset: None,
                shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
                prune_images: false,
            },
        )
        .unwrap();
        (store, runtime)
    };

    // A build for this host, and the same image marked as the other architecture
    let (store, runtime) = open("store");
    let native = build(
        &store,
        &runtime,
        &BuildOptions {
            context_dir: ctx.clone(),
            containerfile: None,
            tag: "app:native".to_owned(),
            build_args: BTreeMap::new(),
            target: None,
            backend: BuildBackend::Native,
            creds: None,
            strict_lint: false,
            no_cache: false,
            squash: false,
            cache_max: None,
            secrets: BTreeMap::new(),
            ssh: BTreeMap::new(),
            jail_params: Vec::new(),
            labels: BTreeMap::new(),
            timestamp: None,
            limits: Default::default(),
        },
    )
    .await
    .unwrap()
    .image;
    let other_arch = if jailer::oci::arch() == "amd64" {
        "arm64"
    } else {
        "amd64"
    };
    let mut config = native.config.clone();
    config.architecture = other_arch.to_owned();
    let pin = store.pin().unwrap();
    let other = store
        .register_built_image(
            &pin,
            &Reference::parse_local_tag("app:other").unwrap(),
            config,
            native.layers.clone(),
            native.layer_descriptors.clone(),
        )
        .await
        .unwrap();
    drop(pin);

    // Two local images
    let target = Reference::parse(&format!("{host}/me/app:1.0")).unwrap();
    let sources = ["app:native".to_owned(), "app:other".to_owned()];
    let index_digest = store
        .push_index(&target, &sources, Some(&creds))
        .await
        .unwrap();
    let (digest, doc) = store
        .client()
        .document(&target, "1.0", Some(&creds))
        .await
        .unwrap();
    assert_eq!(digest, index_digest);
    let archs: Vec<_> = doc
        .manifests
        .unwrap()
        .iter()
        .map(|d| d.platform.clone().unwrap().architecture)
        .collect();
    assert_eq!(archs, [jailer::oci::arch(), other_arch]);

    // A local image and one already in the repository
    let other_tag = Reference::parse(&format!("{host}/me/app:other")).unwrap();
    store
        .push("app:other", &other_tag, Some(&creds))
        .await
        .unwrap();
    let mixed = Reference::parse(&format!("{host}/me/app:mixed")).unwrap();
    let sources = ["app:native".to_owned(), other_tag.to_string()];
    store
        .push_index(&mixed, &sources, Some(&creds))
        .await
        .unwrap();

    // One image per platform
    let dup = ["app:native".to_owned(), "app:native".to_owned()];
    let err = store
        .push_index(&mixed, &dup, Some(&creds))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("two images for"), "{err}");

    // A node pulls the entry for its own architecture
    let (fresh, _) = open("fresh");
    for r in [&target, &mixed] {
        let pulled = fresh
            .pull(&r.to_string(), Some(&creds), "me")
            .await
            .unwrap();
        assert_eq!(pulled.id, native.id);
        assert_ne!(pulled.id, other.id);
    }
}

#[tokio::test]
async fn copy_heredocs_parents_exclude_url_onbuild_and_platform() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = tmp.path().join("ctx");
    for d in ["src/a", "src/b", "src/c", "docs/sub"] {
        std::fs::create_dir_all(ctx.join(d)).unwrap();
    }
    for f in [
        "src/a/Cargo.toml",
        "src/b/Cargo.toml",
        "docs/guide.txt",
        "docs/README.md",
        "docs/sub/x.md",
        "onbuild.txt",
    ] {
        std::fs::write(ctx.join(f), f).unwrap();
    }
    let (addr, _) = start_mock_registry().await;
    let sum = sha256(b"downloaded\n");
    let write_cf = |text: String| std::fs::write(ctx.join("Containerfile"), text).unwrap();
    write_cf(format!(
        r#"# syntax=docker/dockerfile:1
ARG NAME=world
FROM --platform=$BUILDPLATFORM scratch
ARG NAME
ARG TARGETARCH
ONBUILD COPY onbuild.txt /from-onbuild.txt
COPY <<greeting.txt <<"raw.txt" /etc/
hello $NAME on $TARGETARCH
greeting.txt
$NAME
raw.txt
COPY --parents src/*/Cargo.toml /parents/
COPY src/[ab]/Cargo.toml /flat/
COPY --exclude=*.md docs /docs/
ADD --checksum={sum} http://127.0.0.1:{}/files/data.bin /dl/
"#,
        addr.port()
    ));

    let sys = Arc::new(FakeSys::new());
    let client = Client::new().unwrap();
    let store = Arc::new(
        jailer::store::open(sys.clone(), None, &tmp.path().join("store"), client).unwrap(),
    );
    let runtime = JailRuntime::new(
        sys,
        store.clone(),
        Config {
            state_dir: tmp.path().join("containers"),
            dataset: None,
            shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
            prune_images: false,
        },
    )
    .unwrap();
    let opts = |tag: &str| BuildOptions {
        context_dir: ctx.clone(),
        containerfile: None,
        tag: tag.to_owned(),
        build_args: BTreeMap::new(),
        target: None,
        backend: BuildBackend::Native,
        creds: None,
        strict_lint: false,
        no_cache: false,
        squash: false,
        cache_max: None,
        secrets: BTreeMap::new(),
        ssh: BTreeMap::new(),
        jail_params: Vec::new(),
        labels: BTreeMap::new(),
        timestamp: None,
        limits: Default::default(),
    };
    let files = |image: &jailer::store::Image| {
        let root = tmp.path().join(format!("root-{}", &image.id[7..19]));
        store.prepare_rootfs(image, &root, None).unwrap();
        let mut out = BTreeMap::new();
        let mut stack = vec![root.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    let rel = p
                        .strip_prefix(&root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    out.insert(rel, std::fs::read_to_string(&p).unwrap());
                }
            }
        }
        out
    };

    let base = build(&store, &runtime, &opts("base:1"))
        .await
        .unwrap()
        .image;
    assert_eq!(
        base.config.config.on_build,
        ["COPY onbuild.txt /from-onbuild.txt"]
    );
    let got = files(&base);
    let want: BTreeMap<String, String> = [
        (
            "etc/greeting.txt",
            format!("hello world on {}\n", jailer::oci::arch()),
        ),
        ("etc/raw.txt", "$NAME\n".to_owned()),
        ("parents/src/a/Cargo.toml", "src/a/Cargo.toml".to_owned()),
        ("parents/src/b/Cargo.toml", "src/b/Cargo.toml".to_owned()),
        ("flat/Cargo.toml", "src/b/Cargo.toml".to_owned()),
        ("docs/guide.txt", "docs/guide.txt".to_owned()),
        ("dl/data.bin", "downloaded\n".to_owned()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect();
    assert_eq!(got, want);

    // The base's trigger runs in the child's build and is not passed on.
    write_cf("FROM base:1\nCOPY docs/guide.txt /guide.txt\n".to_owned());
    let child = build(&store, &runtime, &opts("child:1"))
        .await
        .unwrap()
        .image;
    assert!(child.config.config.on_build.is_empty());
    let got = files(&child);
    assert_eq!(got["from-onbuild.txt"], "onbuild.txt");
    assert_eq!(got["guide.txt"], "docs/guide.txt");

    // `--squash` leaves the same files in one layer.
    assert!(child.layers.len() > 1);
    let squashed = build(
        &store,
        &runtime,
        &BuildOptions {
            squash: true,
            ..opts("squashed:1")
        },
    )
    .await
    .unwrap()
    .image;
    assert_eq!(squashed.layers.len(), 1);
    assert_eq!(squashed.config.rootfs.diff_ids.len(), 1);
    assert_eq!(files(&squashed), got);

    // `COPY --from` an image, not a stage, named by an ARG.
    write_cf(
        "FROM scratch AS tools\nFROM scratch\nARG SRC=base:1\nCOPY --from=$SRC /etc/raw.txt /docs/ /copied/\nCOPY --from=tools / /empty/\n"
            .to_owned(),
    );
    let copied = build(&store, &runtime, &opts("copied:1"))
        .await
        .unwrap()
        .image;
    let got = files(&copied);
    assert_eq!(got["copied/raw.txt"], "$NAME\n");
    assert_eq!(got["copied/guide.txt"], "docs/guide.txt");
    write_cf("FROM scratch\nCOPY --from=localhost/nowhere:1 /a /a\n".to_owned());
    assert!(build(&store, &runtime, &opts("nowhere:2")).await.is_err());

    // `--label` goes over `LABEL`; `--timestamp` dates the config and this
    // build's history, and an image built twice with it is the same image.
    write_cf("FROM scratch\nLABEL a=file b=file\nCOPY onbuild.txt /o.txt\n".to_owned());
    let stamped = |tag: &'static str| BuildOptions {
        labels: BTreeMap::from([("b".to_owned(), "flag".to_owned())]),
        timestamp: Some(1_700_000_000),
        ..opts(tag)
    };
    let first = build(&store, &runtime, &stamped("stamped:1"))
        .await
        .unwrap()
        .image;
    let labels = &first.config.config.labels;
    assert_eq!(
        (labels["a"].as_str(), labels["b"].as_str()),
        ("file", "flag")
    );
    assert_eq!(first.config.created, "2023-11-14T22:13:20Z");
    assert!(
        first
            .config
            .history
            .iter()
            .all(|h| h.created == "2023-11-14T22:13:20Z")
    );
    let again = build(&store, &runtime, &stamped("stamped:2"))
        .await
        .unwrap()
        .image;
    assert_eq!(again.id, first.id);

    // Failures name the problem.
    for (cf, msg) in [
        (
            "FROM --platform=linux/riscv64 scratch\n",
            "jailer builds for freebsd/",
        ),
        (
            &format!(
                "FROM scratch\nADD --checksum=sha256:{} http://127.0.0.1:{}/files/data.bin /x\n",
                "0".repeat(64),
                addr.port()
            ),
            "checksum is sha256:",
        ),
        (
            &format!(
                "FROM scratch\nADD http://127.0.0.1:{}/files/gone /x\n",
                addr.port()
            ),
            "HTTP 404",
        ),
    ] {
        write_cf(cf.to_owned());
        let err = build(&store, &runtime, &opts("bad:1")).await.unwrap_err();
        assert!(err.to_string().contains(msg), "{err}");
    }
}

#[tokio::test]
async fn cache_trim_drops_least_recently_used_layers() {
    use jailer::store::{CachedLayer, CachedStep};
    let tmp = tempfile::tempdir().unwrap();
    let ctx = tmp.path().join("ctx");
    std::fs::create_dir_all(&ctx).unwrap();
    let sys = Arc::new(FakeSys::new());
    let store = Arc::new(
        jailer::store::open(
            sys.clone(),
            None,
            &tmp.path().join("store"),
            Client::new().unwrap(),
        )
        .unwrap(),
    );
    let runtime = JailRuntime::new(
        sys,
        store.clone(),
        Config {
            state_dir: tmp.path().join("containers"),
            dataset: None,
            shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
            prune_images: false,
        },
    )
    .unwrap();

    // Two one-layer images, each also named by a cache entry; `a` used longer ago.
    let mut built = Vec::new();
    for name in ["a", "b"] {
        std::fs::write(ctx.join(name), name.repeat(1000)).unwrap();
        let cf = ctx.join(format!("{name}.Containerfile"));
        std::fs::write(&cf, format!("FROM scratch\nCOPY {name} /{name}\n")).unwrap();
        let image = build(
            &store,
            &runtime,
            &BuildOptions {
                context_dir: ctx.clone(),
                containerfile: Some(cf),
                tag: format!("{name}:1"),
                build_args: BTreeMap::new(),
                target: None,
                backend: BuildBackend::Native,
                creds: None,
                strict_lint: false,
                no_cache: false,
                squash: false,
                cache_max: None,
                secrets: BTreeMap::new(),
                ssh: BTreeMap::new(),
                jail_params: Vec::new(),
                labels: BTreeMap::new(),
                timestamp: None,
                limits: Default::default(),
            },
        )
        .await
        .unwrap()
        .image;
        jailer::store::record_step(
            &store,
            name,
            &CachedStep {
                layer: Some(CachedLayer {
                    chain: image.layers[0].clone(),
                    diff_id: image.config.rootfs.diff_ids[0].clone(),
                    descriptor: image.layer_descriptors[0].clone(),
                }),
            },
        )
        .unwrap();
        assert!(
            jailer::store::remove(&store, &format!("{name}:1"))
                .await
                .unwrap()
        );
        built.push(image);
    }
    std::fs::File::options()
        .append(true)
        .open(store.dir().join("cache/a"))
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
        .unwrap();
    let layer = |i: usize| store.dir().join("layers").join(&built[i].layers[0]);
    assert!(layer(0).exists() && layer(1).exists());

    assert_eq!(
        jailer::store::trim_cache(&store, u64::MAX).await.unwrap(),
        0
    );
    let b_size = built[1].layer_descriptors[0].size;
    assert_eq!(jailer::store::trim_cache(&store, b_size).await.unwrap(), 1);
    assert!(!layer(0).exists() && layer(1).exists());
    assert_eq!(jailer::store::trim_cache(&store, 0).await.unwrap(), 1);
    assert!(!layer(1).exists());
}
