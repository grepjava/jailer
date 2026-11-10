//! Image signatures as cosign makes them with a key pair: a "simple
//! signing" payload naming the image's manifest digest, signed with ECDSA
//! P-256, pushed as a layer of the manifest tagged `sha256-<hex>.sig` in
//! the image's repository. `cosign verify --key` checks them (with
//! `--insecure-ignore-tlog`, as no transparency log entry is made), and so
//! do `jailer verify` and Legion's image policies: the payload, the keys and
//! the check are Legion's `legion_image::cosign`, so both sides make and
//! read the same bytes. Pushing the signature is jailer's.

use std::collections::BTreeMap;
use std::path::Path;

use legion_image::cosign::{self, VerifyError};
pub use legion_image::cosign::{
    PAYLOAD_TYPE, PrivateKey, PublicKey, SIGNATURE_ANNOTATION, signature_reference,
};

use crate::oci::{Descriptor, Manifest};
use crate::registry::{Client, Credentials, sha256};
use crate::{Error, Reference};

const CONFIG_TYPE: &str = "application/vnd.oci.image.config.v1+json";

/// A private key, PKCS#8 (`PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`) PEM.
pub fn signing_key(pem: &str) -> Result<PrivateKey, Error> {
    PrivateKey::from_pem(pem).map_err(|e| Error::Unsupported(e.to_string()))
}

/// A public key, PKIX (`PUBLIC KEY`) PEM.
pub fn verifying_key(pem: &str) -> Result<PublicKey, Error> {
    PublicKey::from_pem(pem).map_err(|e| Error::Unsupported(e.to_string()))
}

/// Signs the manifest `digest` in `r`'s repository, adding to the
/// signatures already there.
pub async fn sign(
    client: &Client,
    r: &Reference,
    digest: &str,
    key: &PrivateKey,
    creds: Option<&Credentials>,
) -> Result<(), Error> {
    let payload = cosign::payload(r, digest);
    let annotations =
        BTreeMap::from([(SIGNATURE_ANNOTATION.to_owned(), cosign::sign(&payload, key))]);
    let at = cosign::signature_reference(r, digest);
    add_layer(client, r, &at, PAYLOAD_TYPE, &payload, annotations, creds).await
}

/// Adds `body` as a layer of the manifest tagged `at` in `r`'s repository,
/// as cosign keeps signatures and attestations. One already there stays.
pub(crate) async fn add_layer(
    client: &Client,
    r: &Reference,
    at: &Reference,
    media_type: &str,
    body: &[u8],
    annotations: BTreeMap<String, String>,
    creds: Option<&Credentials>,
) -> Result<(), Error> {
    let body_digest = sha256(body);
    let tmp = tempfile::tempdir()?;
    let put = |name: &str, bytes: &[u8]| -> Result<std::path::PathBuf, Error> {
        let path = tmp.path().join(name);
        std::fs::write(&path, bytes)?;
        Ok(path)
    };
    client
        .push_blob(r, &body_digest, &put("body", body)?, creds)
        .await?;

    let mut layers = match client.document(at, at.target(), creds).await {
        Ok((_, doc)) => doc.into_manifest()?.layers,
        Err(legion_image::Error::NotFound(_)) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    if layers
        .iter()
        .any(|l| l.digest == body_digest && l.annotations == annotations)
    {
        return Ok(());
    }
    layers.push(Descriptor {
        media_type: media_type.to_owned(),
        digest: body_digest,
        size: body.len() as u64,
        platform: None,
        annotations,
    });
    // As cosign writes it: one diff id for each layer.
    let config = serde_json::json!({
        "architecture": "",
        "config": {},
        "created": "0001-01-01T00:00:00Z",
        "history": layers.iter().map(|_| serde_json::json!({"created": "0001-01-01T00:00:00Z"})).collect::<Vec<_>>(),
        "os": "",
        "rootfs": {"type": "layers", "diff_ids": layers.iter().map(|l| l.digest.clone()).collect::<Vec<_>>()},
    });
    let config = serde_json::to_vec(&config)?;
    let config_digest = sha256(&config);
    client
        .push_blob(r, &config_digest, &put("config", &config)?, creds)
        .await?;
    let manifest = Manifest::new(
        Descriptor {
            media_type: CONFIG_TYPE.to_owned(),
            digest: config_digest,
            size: config.len() as u64,
            platform: None,
            annotations: BTreeMap::new(),
        },
        layers,
    );
    client.push_manifest(at, &manifest, creds).await?;
    Ok(())
}

/// Checks that `r` (its manifest or index, as pulled) carries a signature
/// by `key`, as Legion's image policies check it: returns the digest signed
/// and the key's fingerprint.
pub async fn verify(
    client: &Client,
    r: &Reference,
    key: &PublicKey,
    creds: Option<&Credentials>,
) -> Result<(String, String), Error> {
    let (digest, _) = client.document(r, r.target(), creds).await?;
    match cosign::verify(client, r, &digest, std::slice::from_ref(key), creds).await {
        Ok(v) => Ok((digest, v.fingerprint)),
        Err(VerifyError::Unsigned) => Err(Error::NotFound(format!("{r} ({digest}) is not signed"))),
        Err(VerifyError::Bad(why)) => Err(Error::NotFound(format!(
            "{r} ({digest}) has no signature by this key: {why}"
        ))),
        Err(e @ VerifyError::CannotFetch(_)) => Err(Error::Runtime(format!("{r} ({digest}): {e}"))),
    }
}

/// Reads a key file, saying which one failed.
pub fn read_key(path: &Path) -> Result<String, Error> {
    std::fs::read_to_string(path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", path.display()),
        ))
    })
}
