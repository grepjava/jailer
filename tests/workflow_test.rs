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
use jailer::runtime::{JailRuntime, RuntimeConfig};
use jailer::store::Store;
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

    let sys = Arc::new(FakeSys::new(false));
    let client = Client::new().unwrap().plain_http(&registry_host);
    let store_dir = tmp.path().join("store1");
    let store = Arc::new(Store::open(sys.clone(), None, &store_dir, client).unwrap());
    let runtime = JailRuntime::new(
        sys,
        store.clone(),
        RuntimeConfig {
            state_dir: tmp.path().join("containers1"),
            dataset: None,
            shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
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

    let sys2 = Arc::new(FakeSys::new(false));
    let client2 = Client::new().unwrap().plain_http(&registry_host);
    let store2 = Arc::new(Store::open(sys2, None, &tmp.path().join("store2"), client2).unwrap());
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

    let sys3 = Arc::new(FakeSys::new(true));
    let client3 = Client::new().unwrap().plain_http(&registry_host);
    let store3 = Arc::new(
        Store::open(
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
    assert!(store.remove("demo:1.0").await.unwrap());
    assert!(std::fs::read_dir(&blobs).unwrap().next().is_some());
    drop(pin);
    assert!(!store.remove("demo:1.0").await.unwrap());
    assert_eq!(std::fs::read_dir(&blobs).unwrap().count(), 0);
}
