//! Image signatures as cosign makes them with a key pair: a "simple
//! signing" payload naming the image's manifest digest, signed with ECDSA
//! P-256, pushed as a layer of the manifest tagged `sha256-<hex>.sig` in
//! the image's repository. `cosign verify --key` checks them (with
//! `--insecure-ignore-tlog`, as no transparency log entry is made), and so
//! does `jailer verify`.

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use p256::{PublicKey, SecretKey};
use serde_json::json;

use crate::oci::{Descriptor, Manifest};
use crate::registry::{Client, Credentials, sha256};
use crate::{Error, Reference};

pub const PAYLOAD_TYPE: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
pub const SIGNATURE: &str = "dev.cosignproject.cosign/signature";
const CONFIG_TYPE: &str = "application/vnd.oci.image.config.v1+json";

fn bad_key(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Unsupported(format!("{what}: {e}"))
}

/// A new key pair: the private key as PKCS#8 PEM, the public as PKIX PEM.
pub fn generate() -> Result<(String, String), Error> {
    let secret = loop {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("random bytes");
        if let Ok(k) = SecretKey::from_slice(&bytes) {
            break k;
        }
    };
    let private = secret
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| bad_key("writing the private key", e))?;
    let public = secret
        .public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| bad_key("writing the public key", e))?;
    Ok((private.to_string(), public))
}

/// A private key, PKCS#8 (`PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`) PEM.
pub fn signing_key(pem: &str) -> Result<SigningKey, Error> {
    let secret = SecretKey::from_pkcs8_pem(pem)
        .or_else(|_| SecretKey::from_sec1_pem(pem))
        .map_err(|e| bad_key("not an unencrypted P-256 private key", e))?;
    Ok(SigningKey::from(&secret))
}

pub fn verifying_key(pem: &str) -> Result<VerifyingKey, Error> {
    let public =
        PublicKey::from_public_key_pem(pem).map_err(|e| bad_key("not a P-256 public key", e))?;
    Ok(VerifyingKey::from(&public))
}

/// What is signed: the image's repository and manifest digest.
pub fn payload(r: &Reference, digest: &str) -> Vec<u8> {
    let doc = json!({
        "critical": {
            "identity": {"docker-reference": format!("{}/{}", r.registry, r.repository)},
            "image": {"docker-manifest-digest": digest},
            "type": "cosign container image signature",
        },
        "optional": null,
    });
    serde_json::to_vec(&doc).expect("JSON")
}

/// The tag a manifest's signatures are kept under.
pub fn signature_ref(r: &Reference, digest: &str) -> Reference {
    Reference {
        tag: Some(format!("{}.sig", digest.replacen(':', "-", 1))),
        digest: None,
        ..r.clone()
    }
}

/// Signs the manifest `digest` in `r`'s repository, adding to the
/// signatures already there.
pub async fn sign(
    client: &Client,
    r: &Reference,
    digest: &str,
    key: &SigningKey,
    creds: Option<&Credentials>,
) -> Result<(), Error> {
    let payload = payload(r, digest);
    let signature: Signature = key.sign(&payload);
    let signature = B64.encode(signature.to_der().as_bytes());
    let annotations = BTreeMap::from([(SIGNATURE.to_owned(), signature)]);
    let at = signature_ref(r, digest);
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
    let config = json!({
        "architecture": "",
        "config": {},
        "created": "0001-01-01T00:00:00Z",
        "history": layers.iter().map(|_| json!({"created": "0001-01-01T00:00:00Z"})).collect::<Vec<_>>(),
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
/// by `key`; returns the digest signed.
pub async fn verify(
    client: &Client,
    r: &Reference,
    key: &VerifyingKey,
    creds: Option<&Credentials>,
) -> Result<String, Error> {
    let (digest, _) = client.document(r, r.target(), creds).await?;
    let sig_ref = signature_ref(r, &digest);
    let layers = match client.document(&sig_ref, sig_ref.target(), creds).await {
        Ok((_, doc)) => doc.into_manifest()?.layers,
        Err(legion_image::Error::NotFound(_)) => {
            return Err(Error::NotFound(format!("{r} ({digest}) is not signed")));
        }
        Err(e) => return Err(e.into()),
    };
    let tmp = tempfile::tempdir()?;
    for (i, layer) in layers.iter().enumerate() {
        let Some(signature) = layer.annotations.get(SIGNATURE) else {
            continue;
        };
        let Ok(signature) = B64
            .decode(signature)
            .map_err(|_| ())
            .and_then(|der| Signature::from_der(&der).map_err(|_| ()))
        else {
            continue;
        };
        let path = tmp.path().join(i.to_string());
        client
            .blob(&sig_ref, &layer.digest, layer.size, &path, creds)
            .await?;
        let payload = std::fs::read(&path)?;
        if key.verify(&payload, &signature).is_err() {
            continue;
        }
        // A payload this key signed that is not an image signature, or
        // not of this image, is passed over for the next.
        let Ok(signed) = serde_json::from_slice::<serde_json::Value>(&payload) else {
            continue;
        };
        if signed["critical"]["type"] == "cosign container image signature"
            && signed["critical"]["image"]["docker-manifest-digest"] == digest.as_str()
        {
            return Ok(digest);
        }
    }
    Err(Error::NotFound(format!(
        "{r} ({digest}) has no signature by this key"
    )))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_sign_and_verify_payloads() {
        let (private, public) = generate().unwrap();
        assert!(private.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(public.starts_with("-----BEGIN PUBLIC KEY-----"));
        let r = Reference::parse("ghcr.io/me/app:1").unwrap();
        let payload = payload(&r, "sha256:abc");
        let text = String::from_utf8(payload.clone()).unwrap();
        assert!(
            text.contains("\"docker-reference\":\"ghcr.io/me/app\""),
            "{text}"
        );
        let sig: Signature = signing_key(&private).unwrap().sign(&payload);
        let key = verifying_key(&public).unwrap();
        assert!(key.verify(&payload, &sig).is_ok());
        assert!(key.verify(b"something else", &sig).is_err());
        assert_eq!(
            signature_ref(&r, "sha256:abc").to_string(),
            "ghcr.io/me/app:sha256-abc.sig"
        );
        assert!(signing_key(&public).is_err());
    }
}
