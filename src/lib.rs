//! `jailer`: a standalone FreeBSD OCI image builder, local jail test runner,
//! compatibility checker, and registry publisher aligned with Legion's runtime.

pub mod auth;
pub mod build;
pub mod check;
pub mod containerfile;
pub mod init;
pub mod layer;
pub mod log;
pub mod oci;
pub mod reference;
pub mod registry;
pub mod runtime;
pub mod shim;
pub mod state;
pub mod store;
pub mod sys;
pub mod users;

pub use oci::{Config, ImageConfig};
pub use reference::{Reference, registry_of};
pub use registry::{Client, Credentials};
pub use store::{Image, StorageMode, Store, chain_ids};

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
