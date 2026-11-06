//! `jailer`: a standalone FreeBSD OCI image builder, local jail test runner,
//! compatibility checker, and registry publisher aligned with Legion's runtime.
//! Images (references, the registry client, the store, layers) are Legion's
//! own `legion-image`, containers are `legion-jail`'s, and the system
//! calls `legion-sys`.

pub mod auth;
pub mod build;
pub mod cache;
pub mod check;
pub mod containerfile;
pub mod init;
pub mod layer;
pub mod net;
pub mod record;
pub mod runtime;
pub mod sign;
pub mod store;

pub use legion_jail::{log, shim, state, users};

pub use legion_image::oci;
pub use legion_image::{Client, Credentials, Reference, registry_of};
pub use oci::{Config, ImageConfig};
pub use store::{Image, StorageMode, Store, chain_ids};

pub mod registry {
    pub use legion_image::{Client, Credentials, sha256};
}

/// An HTTP client builder for jailer's own requests. TLS uses ring, as
/// Legion's registry client does: the one reqwest and rustls build.
pub(crate) fn http_client() -> reqwest::ClientBuilder {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder().user_agent(concat!("jailer/", env!("CARGO_PKG_VERSION")))
}

pub mod sys {
    pub use legion_sys::*;

    /// Whether this host has a ZFS pool to keep images in.
    pub fn zfs_available() -> bool {
        std::process::Command::new("zfs")
            .args(["list", "-H", "-d", "0"])
            .output()
            .is_ok_and(|o| o.status.success() && !o.stdout.is_empty())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("image reference {0}")]
    Reference(String),
    #[error("{0}")]
    Registry(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{what}: digest {got}, expected {expected}")]
    Digest {
        what: String,
        expected: String,
        got: String,
    },
    #[error("{0}")]
    Unsupported(String),
    #[error("extracting a layer: {0}")]
    Extract(String),
    #[error("{0}")]
    Build(String),
    #[error("{0}")]
    Runtime(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Sys(#[from] sys::Error),
}

impl From<legion_runtime::Error> for Error {
    fn from(e: legion_runtime::Error) -> Self {
        use legion_runtime::Error as E;
        match e {
            E::NotFound(s) => Error::NotFound(s),
            E::Io(e) => Error::Io(e),
            e => Error::Runtime(e.to_string()),
        }
    }
}

impl From<legion_image::Error> for Error {
    fn from(e: legion_image::Error) -> Self {
        use legion_image::Error as E;
        match e {
            E::Reference(s) => Error::Reference(s),
            E::Registry(s) => Error::Registry(s),
            E::NotFound(s) => Error::NotFound(s),
            E::Digest {
                what,
                expected,
                got,
            } => Error::Digest {
                what,
                expected,
                got,
            },
            E::Unsupported(s) | E::Platform(s) => Error::Unsupported(s),
            E::Extract(s) => Error::Extract(s),
            E::Io(e) => Error::Io(e),
            E::Json(e) => Error::Json(e),
            E::Sys(e) => Error::Sys(e),
        }
    }
}
