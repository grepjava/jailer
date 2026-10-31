//! Image references: `[registry/]repository[:tag][@digest]`, as Docker,
//! Podman, and Legion read them.

use std::fmt;

use crate::Error;

const DOCKER_HUB: &str = "docker.io";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Reference {
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl Reference {
    pub fn parse(s: &str) -> Result<Reference, Error> {
        let bad = |why: &str| Error::Reference(format!("{s:?}: {why}"));
        let (name, digest) = match s.split_once('@') {
            Some((n, d)) => {
                let hex = d
                    .strip_prefix("sha256:")
                    .ok_or_else(|| bad("only sha256 digests"))?;
                if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(bad("bad digest"));
                }
                (n, Some(d.to_ascii_lowercase()))
            }
            None => (s, None),
        };
        // A tag follows the last `:` after the last `/`; a `:` before it is
        // a registry's port.
        let slash = name.rfind('/').map_or(0, |i| i + 1);
        let (name, tag) = match name[slash..].rfind(':') {
            Some(i) => (&name[..slash + i], Some(name[slash + i + 1..].to_owned())),
            None => (name, None),
        };
        if let Some(t) = &tag {
            let ok = !t.is_empty()
                && t.len() <= 128
                && t.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
            if !ok {
                return Err(bad("bad tag"));
            }
        }
        let (registry, repository) = match name.split_once('/') {
            Some((first, rest)) if first.contains(['.', ':']) || first == "localhost" => {
                (first.to_owned(), rest.to_owned())
            }
            _ => (DOCKER_HUB.to_owned(), name.to_owned()),
        };
        let repository = if registry == DOCKER_HUB && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository
        };
        let ok = !repository.is_empty()
            && repository.split('/').all(|c| {
                !c.is_empty()
                    && c.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)
                    })
            });
        if !ok {
            return Err(bad("bad repository name"));
        }
        let tag = match (&tag, &digest) {
            (None, None) => Some("latest".to_owned()),
            _ => tag,
        };
        Ok(Reference {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// Parses a local build tag: a bare name like `myapp:latest` without a
    /// registry prefix becomes `localhost/myapp:latest` (Podman/Buildah's
    /// convention for locally built images, which Legion's `IMAGES.md`
    /// recommends for images loaded without a registry).
    pub fn parse_local_tag(s: &str) -> Result<Reference, Error> {
        let slash = s.rfind('/').map_or(0, |i| i + 1);
        let before_tag = match s[slash..].rfind(':') {
            Some(i) => &s[..slash + i],
            None => s,
        };
        let has_explicit_registry = match before_tag.split_once('/') {
            Some((first, _)) => first.contains(['.', ':']) || first == "localhost",
            None => false,
        };
        if has_explicit_registry {
            Self::parse(s)
        } else {
            Self::parse(&format!("localhost/{s}"))
        }
    }

    /// The host to talk to: Docker Hub's API is not at `docker.io`.
    pub fn host(&self) -> &str {
        if self.registry == DOCKER_HUB {
            "registry-1.docker.io"
        } else {
            &self.registry
        }
    }

    /// What to ask the registry for: the digest if there is one.
    pub fn target(&self) -> &str {
        self.digest
            .as_deref()
            .or(self.tag.as_deref())
            .unwrap_or("latest")
    }

    /// `localhost/...` names images built or loaded on the node, which no
    /// registry serves (Podman's convention).
    pub fn is_local(&self) -> bool {
        self.registry == "localhost"
    }
}

/// The registry a Docker config's `auths` key names, as a [`Reference`]
/// names it: `https://index.docker.io/v1/` is `docker.io`,
/// `https://ghcr.io` is `ghcr.io`.
pub fn registry_of(key: &str) -> String {
    let key = key
        .strip_prefix("https://")
        .or_else(|| key.strip_prefix("http://"))
        .unwrap_or(key);
    let host = key.split('/').next().unwrap_or("").to_ascii_lowercase();
    match host.as_str() {
        "index.docker.io" | "registry-1.docker.io" | "registry.hub.docker.com" => {
            DOCKER_HUB.to_owned()
        }
        _ => host,
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.registry, self.repository)?;
        if let Some(t) = &self.tag {
            write!(f, ":{t}")?;
        }
        if let Some(d) = &self.digest {
            write!(f, "@{d}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(s: &str) -> String {
        Reference::parse(s).unwrap().to_string()
    }

    #[test]
    fn references_and_local_tags() {
        assert_eq!(canonical("nginx"), "docker.io/library/nginx:latest");
        assert_eq!(
            canonical("freebsd/freebsd-runtime:15.1"),
            "docker.io/freebsd/freebsd-runtime:15.1"
        );
        assert_eq!(
            Reference::parse_local_tag("myapp").unwrap().to_string(),
            "localhost/myapp:latest"
        );
        assert_eq!(
            Reference::parse_local_tag("myapp:1.0").unwrap().to_string(),
            "localhost/myapp:1.0"
        );
        assert_eq!(
            Reference::parse_local_tag("ghcr.io/me/app:v1")
                .unwrap()
                .to_string(),
            "ghcr.io/me/app:v1"
        );
    }
}
