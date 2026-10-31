//! A registry the tests push to and pull from: blobs and manifests kept in
//! memory, and `/files/...` for `ADD <url>`.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use jailer::registry::sha256;

#[derive(Default)]
pub struct MockRegistry {
    pub blobs: Mutex<BTreeMap<String, Vec<u8>>>,
    pub manifests: Mutex<BTreeMap<String, (String, Vec<u8>)>>,
}

pub async fn start_mock_registry() -> (SocketAddr, Arc<MockRegistry>) {
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
