//! The OCI (and Docker v2) documents an image is made of.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Error;

pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
pub const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
pub const OCI_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
pub const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";

/// What a client accepts when asking for a manifest.
pub const MANIFEST_TYPES: [&str; 4] = [OCI_INDEX, DOCKER_LIST, OCI_MANIFEST, DOCKER_MANIFEST];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub media_type: String,
    pub digest: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
}

/// An index or a manifest, told apart by their contents: some registries
/// leave `mediaType` out.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifests: Option<Vec<Descriptor>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Descriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub media_type: String,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl Manifest {
    pub fn new(config: Descriptor, layers: Vec<Descriptor>) -> Self {
        Self {
            schema_version: 2,
            media_type: OCI_MANIFEST.to_owned(),
            config,
            layers,
            annotations: BTreeMap::new(),
        }
    }
}

impl Document {
    pub fn parse(bytes: &[u8]) -> Result<Document, Error> {
        let d: Document = serde_json::from_slice(bytes)
            .map_err(|e| Error::Unsupported(format!("not an image manifest: {e}")))?;
        if d.schema_version == 1 {
            return Err(Error::Unsupported(
                "Docker schema 1 manifests are not supported".to_owned(),
            ));
        }
        Ok(d)
    }

    pub fn into_manifest(self) -> Result<Manifest, Error> {
        let config = self
            .config
            .ok_or_else(|| Error::Unsupported("a manifest without a config".to_owned()))?;
        Ok(Manifest {
            schema_version: if self.schema_version == 0 {
                2
            } else {
                self.schema_version
            },
            media_type: if self.media_type.is_empty() {
                OCI_MANIFEST.to_owned()
            } else {
                self.media_type
            },
            config,
            layers: self.layers,
            annotations: self.annotations,
        })
    }
}

/// This node's architecture in OCI's words.
pub fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "powerpc64" => "ppc64",
        "riscv64" => "riscv64",
        other => other,
    }
}

/// The entry of an index for `arch` and the first of `oses`, in order of
/// preference, that it offers.
pub fn select<'a>(manifests: &'a [Descriptor], oses: &[&str]) -> Result<&'a Descriptor, Error> {
    select_for_arch(manifests, oses, arch())
}

pub fn select_for_arch<'a>(
    manifests: &'a [Descriptor],
    oses: &[&str],
    arch: &str,
) -> Result<&'a Descriptor, Error> {
    oses.iter()
        .find_map(|os| {
            manifests.iter().find(|m| {
                m.platform
                    .as_ref()
                    .is_some_and(|p| p.os == *os && p.architecture == arch)
            })
        })
        .ok_or_else(|| {
            let offered: Vec<String> = manifests
                .iter()
                .filter_map(|m| m.platform.as_ref())
                .map(|p| format!("{}/{}", p.os, p.architecture))
                .collect();
            let wanted: Vec<String> = oses.iter().map(|os| format!("{os}/{arch}")).collect();
            Error::Unsupported(format!(
                "no image for {} (offered: {})",
                wanted.join(" or "),
                if offered.is_empty() {
                    "none".to_owned()
                } else {
                    offered.join(", ")
                }
            ))
        })
}

/// An image's configuration file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub architecture: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default)]
    pub config: Config,
    #[serde(default)]
    pub rootfs: RootFs,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<History>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootFs {
    #[serde(rename = "type", default = "default_rootfs_type")]
    pub kind: String,
    #[serde(default)]
    pub diff_ids: Vec<String>,
}

fn default_rootfs_type() -> String {
    "layers".to_owned()
}

impl Default for RootFs {
    fn default() -> Self {
        Self {
            kind: default_rootfs_type(),
            diff_ids: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct History {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created_by: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub empty_layer: bool,
}

/// How to run the image. FreeBSD's own images write these keys in lower
/// case (`cmd`), so both spellings are read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(
        rename = "Entrypoint",
        alias = "entrypoint",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub entrypoint: Vec<String>,
    #[serde(
        rename = "Cmd",
        alias = "cmd",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub cmd: Vec<String>,
    #[serde(
        rename = "Env",
        alias = "env",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub env: Vec<String>,
    #[serde(
        rename = "User",
        alias = "user",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub user: String,
    #[serde(
        rename = "WorkingDir",
        alias = "workingdir",
        alias = "working_dir",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub working_dir: String,
    #[serde(
        rename = "StopSignal",
        alias = "stopsignal",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub stop_signal: String,
    #[serde(
        rename = "Labels",
        alias = "labels",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub labels: BTreeMap<String, String>,
    #[serde(
        rename = "ExposedPorts",
        alias = "exposedports",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub exposed_ports: BTreeMap<String, serde_json::Value>,
    #[serde(
        rename = "Volumes",
        alias = "volumes",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub volumes: BTreeMap<String, serde_json::Value>,
    /// `ONBUILD` instructions, run by builds that use the image as a base.
    #[serde(
        rename = "OnBuild",
        alias = "onbuild",
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub on_build: Vec<String>,
}

fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configs_in_either_case() {
        let freebsd: ImageConfig = serde_json::from_str(
            r#"{"architecture":"amd64","os":"freebsd","config":{"cmd":["/bin/sh"]},
                "rootfs":{"type":"layers","diff_ids":["sha256:aa"]}}"#,
        )
        .unwrap();
        assert_eq!(freebsd.config.cmd, ["/bin/sh"]);
        let docker: ImageConfig = serde_json::from_str(
            r#"{"config":{"Entrypoint":null,"Cmd":["x"],"Env":["A=1"],"User":"www",
                "WorkingDir":"/srv","Labels":null}}"#,
        )
        .unwrap();
        assert_eq!(docker.config.cmd, ["x"]);
        assert!(docker.config.entrypoint.is_empty());
        assert_eq!(docker.config.user, "www");
        assert_eq!(docker.config.working_dir, "/srv");
        let none: ImageConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(none, ImageConfig::default());
    }

    #[test]
    fn selects_this_platform() {
        let arch = arch();
        let list: Vec<Descriptor> = serde_json::from_value(serde_json::json!([
            {"digest": "sha256:l", "platform": {"os": "linux", "architecture": arch}},
            {"digest": "sha256:o", "platform": {"os": "freebsd", "architecture": "other"}},
            {"digest": "sha256:f", "platform": {"os": "freebsd", "architecture": arch}},
        ]))
        .unwrap();
        let both = ["freebsd", "linux"];
        assert_eq!(select(&list, &["freebsd"]).unwrap().digest, "sha256:f");
        assert_eq!(select(&list, &both).unwrap().digest, "sha256:f");
        assert_eq!(select(&list[..2], &both).unwrap().digest, "sha256:l");
    }
}
