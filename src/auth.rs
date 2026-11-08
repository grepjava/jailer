//! Docker and Podman registry authentication (`~/.docker/config.json`,
//! `$REGISTRY_AUTH_FILE`, `$XDG_RUNTIME_DIR/containers/auth.json`), matching
//! the format Legion's `imagePullSecrets` reads.

use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::Error;
use crate::registry::Credentials;
use crate::registry_of;

/// Where a command's registry credentials come from, looked up for each
/// registry it talks to: `--creds`, else `--authfile` or the standard files.
#[derive(Debug, Clone, Default)]
pub struct CredsSource {
    pub creds: Option<String>,
    pub authfile: Option<PathBuf>,
}

impl CredsSource {
    pub fn for_registry(&self, registry: &str) -> Result<Option<Credentials>, Error> {
        resolve_credentials(registry, self.creds.as_deref(), self.authfile.as_deref())
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

/// The login for `registry` in a Docker or Podman auth file, as Legion
/// reads a person's: entries with nothing usable are passed over.
pub fn from_json(text: &str, registry: &str) -> Result<Option<Credentials>, Error> {
    let logins = legion_api::login::docker_config_lenient(text.as_bytes())
        .map_err(|e| Error::Registry(format!("parsing auth config: {e}")))?;
    Ok(Credentials::for_registry(&logins, &registry_of(registry)))
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
    // Only this registry's entry changes: the file's other settings
    // (`credsStore`, `credHelpers`, other registries) are kept, and a file
    // that does not parse is left alone.
    let mut cfg: serde_json::Value = match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text)
            .map_err(|e| Error::Registry(format!("{}: not an auth file: {e}", path.display())))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(e) => return Err(e.into()),
    };
    let not_object = || Error::Registry(format!("{}: not an auth file", path.display()));
    let auths = cfg
        .as_object_mut()
        .ok_or_else(not_object)?
        .entry("auths")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(not_object)?;
    let encoded = STANDARD.encode(format!("{}:{}", creds.username, creds.password));
    // Another spelling of the same registry, as `https://ghcr.io` for
    // `ghcr.io`, would be read before this entry or after it: it goes.
    let target = registry_of(registry);
    auths.retain(|k, _| registry_of(k) != target);
    auths.insert(registry.to_owned(), serde_json::json!({ "auth": encoded }));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(&cfg)?;
    // A new file is its owner's alone from the start; one there already
    // (or a link to one, as dotfiles keep it) is written in place.
    let mut file = std::fs::OpenOptions::new();
    file.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut file, 0o600);
    std::io::Write::write_all(&mut file.open(&path)?, &bytes)?;
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
    fn auth_wins_and_an_entry_needs_a_login() {
        let read = |entry: &str| {
            from_json(
                &format!(r#"{{"auths": {{"ghcr.io": {entry}}}}}"#),
                "ghcr.io",
            )
            .unwrap()
            .map(|c| (c.username, c.password))
        };
        let pair = |u: &str, p: &str| Some((u.to_owned(), p.to_owned()));
        // Y2k6c2VjcmV0 is ci:secret.
        assert_eq!(
            read(r#"{"auth": "Y2k6c2VjcmV0", "username": "me", "password": "tok"}"#),
            pair("ci", "secret")
        );
        // A bad `auth` is not passed over for the rest of the entry.
        assert_eq!(
            read(r#"{"auth": "%%%", "username": "me", "password": "tok"}"#),
            None
        );
        assert_eq!(read(r#"{"username": "me"}"#), pair("me", ""));
        assert_eq!(read(r#"{"password": "tok"}"#), pair("", "tok"));
        assert_eq!(read(r#"{"auth": "", "identitytoken": "x"}"#), None);
        assert_eq!(read("{}"), None);
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

    #[test]
    fn a_config_with_no_logins_is_none() {
        // As Docker writes one before any login, or with a credential store.
        for json in [
            "{}",
            r#"{"auths": {}}"#,
            r#"{"credsStore": "desktop"}"#,
            r#"{"psFormat": "table {{.ID}}", "proxies": {"default": {"httpProxy": "http://p:3128"}}}"#,
            r#"{"auths": {"ghcr.io": {}}, "credsStore": "desktop", "currentContext": "x"}"#,
        ] {
            assert!(from_json(json, "ghcr.io").unwrap().is_none(), "{json}");
        }
        assert!(from_json("{not json", "ghcr.io").is_err());
    }

    #[test]
    fn saving_keeps_the_files_other_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(
            &path,
            r#"{"auths": {"quay.io": {"auth": "eDp5"}, "https://ghcr.io": {"auth": "b2xkOm9sZA=="}},
                "credsStore": "pass",
                "credHelpers": {"gcr.io": "gcloud"}}"#,
        )
        .unwrap();
        let creds = Credentials {
            username: "me".to_owned(),
            password: "tok".to_owned(),
        };
        save_credentials("ghcr.io", &creds, Some(&path)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["credsStore"], "pass");
        assert_eq!(v["credHelpers"]["gcr.io"], "gcloud");
        assert_eq!(v["auths"]["quay.io"]["auth"], "eDp5");
        assert!(v["auths"].get("https://ghcr.io").is_none());
        let g = from_json(&text, "ghcr.io").unwrap().unwrap();
        assert_eq!((g.username.as_str(), g.password.as_str()), ("me", "tok"));

        // A file that does not parse is not replaced.
        std::fs::write(&path, "{not json").unwrap();
        assert!(save_credentials("ghcr.io", &creds, Some(&path)).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not json");
    }
}
