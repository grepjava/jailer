//! Docker and Podman registry authentication (`~/.docker/config.json`,
//! `$REGISTRY_AUTH_FILE`, `$XDG_RUNTIME_DIR/containers/auth.json`), matching
//! the format Legion's `imagePullSecrets` reads.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::reference::registry_of;
use crate::registry::Credentials;

#[derive(Debug, Default, Serialize, Deserialize)]
struct AuthFile {
    #[serde(default)]
    auths: BTreeMap<String, AuthEntry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AuthEntry {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    auth: String,
}

impl AuthEntry {
    fn into_credentials(self) -> Option<Credentials> {
        if !self.username.is_empty() || !self.password.is_empty() {
            return Some(Credentials {
                username: self.username,
                password: self.password,
            });
        }
        if !self.auth.is_empty() {
            let decoded = STANDARD.decode(self.auth.trim()).ok()?;
            let text = String::from_utf8(decoded).ok()?;
            let (u, p) = text.split_once(':')?;
            return Some(Credentials {
                username: u.to_owned(),
                password: p.to_owned(),
            });
        }
        None
    }
}

/// Parses `--creds user[:password]` or resolves credentials for `registry`
/// from `authfile` or standard Docker/Podman auth file locations.
pub fn resolve_credentials(
    registry: &str,
    creds_flag: Option<&str>,
    authfile: Option<&Path>,
) -> Result<Option<Credentials>, Error> {
    if let Some(c) = creds_flag {
        let (u, p) = match c.split_once(':') {
            Some((u, p)) => (u.to_owned(), p.to_owned()),
            None => (c.to_owned(), String::new()),
        };
        return Ok(Some(Credentials {
            username: u,
            password: p,
        }));
    }
    if let Some(path) = authfile {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Registry(format!("reading auth file {}: {e}", path.display())))?;
        return from_json(&text, registry);
    }
    for path in default_auth_paths() {
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Some(creds) = from_json(&text, registry)?
        {
            return Ok(Some(creds));
        }
    }
    Ok(None)
}

pub fn from_json(text: &str, registry: &str) -> Result<Option<Credentials>, Error> {
    let parsed: AuthFile = serde_json::from_str(text)
        .map_err(|e| Error::Registry(format!("parsing auth config: {e}")))?;
    let target = registry_of(registry);
    for (key, entry) in parsed.auths {
        if registry_of(&key) == target
            && let Some(c) = entry.into_credentials()
        {
            return Ok(Some(c));
        }
    }
    Ok(None)
}

/// Saves credentials for `registry` into `authfile` (or `~/.docker/config.json`).
pub fn save_credentials(
    registry: &str,
    creds: &Credentials,
    authfile: Option<&Path>,
) -> Result<PathBuf, Error> {
    let path = match authfile {
        Some(p) => p.to_path_buf(),
        None => default_write_auth_path()?,
    };
    let mut cfg: AuthFile = match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => AuthFile::default(),
    };
    let encoded = STANDARD.encode(format!("{}:{}", creds.username, creds.password));
    cfg.auths.insert(
        registry.to_owned(),
        AuthEntry {
            username: String::new(),
            password: String::new(),
            auth: encoded,
        },
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(&cfg)?;
    std::fs::write(&path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

fn default_auth_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(p) = std::env::var("REGISTRY_AUTH_FILE") {
        paths.push(PathBuf::from(p));
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        paths.push(PathBuf::from(xdg).join("containers").join("auth.json"));
    }
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let home = PathBuf::from(home);
        paths.push(home.join(".docker").join("config.json"));
        paths.push(home.join(".config").join("containers").join("auth.json"));
    }
    paths
}

fn default_write_auth_path() -> Result<PathBuf, Error> {
    if let Ok(p) = std::env::var("REGISTRY_AUTH_FILE") {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| Error::Registry("HOME is not set".to_owned()))?;
    Ok(PathBuf::from(home).join(".docker").join("config.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_username_password_and_base64_auth() {
        let json = r#"{
            "auths": {
                "https://index.docker.io/v1/": {"auth": "Y2k6c2VjcmV0"},
                "ghcr.io": {"username": "me", "password": "tok"}
            }
        }"#;
        let d = from_json(json, "docker.io").unwrap().unwrap();
        assert_eq!((d.username.as_str(), d.password.as_str()), ("ci", "secret"));
        let g = from_json(json, "ghcr.io").unwrap().unwrap();
        assert_eq!((g.username.as_str(), g.password.as_str()), ("me", "tok"));
        assert!(from_json(json, "quay.io").unwrap().is_none());
    }
}
