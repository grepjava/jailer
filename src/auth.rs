//! Docker and Podman registry authentication (`~/.docker/config.json`,
//! `$REGISTRY_AUTH_FILE`, `$XDG_RUNTIME_DIR/containers/auth.json`), matching
//! the format Legion's `imagePullSecrets` reads.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::registry::Credentials;
use crate::registry_of;

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

/// Checks `creds` with `registry` as `docker login` does: asks for the
/// registry's API root, and when that wants a login, gives the credentials
/// to it (Basic) or to the token service it names (Bearer). A registry that
/// asks for no login takes any credentials.
pub async fn check_credentials(
    registry: &str,
    creds: &Credentials,
    plain_http: bool,
) -> Result<(), Error> {
    let registry = registry_of(registry);
    // Docker Hub's API is not at `docker.io`.
    let host = if registry == "docker.io" {
        "registry-1.docker.io"
    } else {
        registry.as_str()
    };
    let scheme = if plain_http { "http" } else { "https" };
    let fail = |e: String| Error::Registry(format!("{registry}: {e}"));
    let refused = || {
        Error::Registry(format!(
            "{registry}: login refused for {}: wrong username, password or token",
            creds.username
        ))
    };
    let http = reqwest::Client::builder()
        .user_agent(concat!("jailer/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| fail(e.to_string()))?;
    let root = format!("{scheme}://{host}/v2/");
    let resp = http
        .get(&root)
        .send()
        .await
        .map_err(|e| fail(e.to_string()))?;
    if resp.status().is_success() {
        return Ok(());
    }
    if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Err(fail(format!("HTTP {} from {root}", resp.status())));
    }
    let challenge = resp
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let (kind, params) = challenge.split_once(' ').unwrap_or((&challenge, ""));
    let req = if kind.eq_ignore_ascii_case("basic") {
        http.get(&root)
    } else if kind.eq_ignore_ascii_case("bearer") {
        let params = parse_challenge(params);
        let realm = params
            .get("realm")
            .ok_or_else(|| fail(format!("auth challenge without realm: {challenge}")))?;
        let mut query = vec![("account", creds.username.as_str())];
        if let Some(service) = params.get("service") {
            query.push(("service", service));
        }
        http.get(realm).query(&query)
    } else {
        return Err(fail(format!("unknown auth challenge: {challenge}")));
    };
    let resp = req
        .basic_auth(&creds.username, Some(&creds.password))
        .send()
        .await
        .map_err(|e| fail(e.to_string()))?;
    match resp.status() {
        s if s.is_success() => Ok(()),
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => Err(refused()),
        s => Err(fail(format!("HTTP {s} logging in"))),
    }
}

/// `realm="...",service="..."`, the parameters of an auth challenge.
fn parse_challenge(s: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut rest = s.trim();
    while let Some((key, after)) = rest.split_once('=') {
        let key = key
            .trim()
            .trim_start_matches(',')
            .trim()
            .to_ascii_lowercase();
        let (value, next) = match after.strip_prefix('"') {
            Some(quoted) => match quoted.find('"') {
                Some(end) => (&quoted[..end], &quoted[end + 1..]),
                None => (quoted, ""),
            },
            None => match after.find(',') {
                Some(end) => (&after[..end], &after[end..]),
                None => (after, ""),
            },
        };
        out.insert(key, value.to_owned());
        rest = next.trim_start_matches(',').trim();
    }
    out
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
    fn challenges_give_realm_and_service() {
        let p = parse_challenge(
            r#"realm="https://ghcr.io/token",service="ghcr.io",scope="repository:a/b:pull""#,
        );
        assert_eq!(p["realm"], "https://ghcr.io/token");
        assert_eq!(p["service"], "ghcr.io");
        let p = parse_challenge(r#"realm=https://r/t, service="a,b""#);
        assert_eq!(p["realm"], "https://r/t");
        assert_eq!(p["service"], "a,b");
    }

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
