//! `jailer init`: scaffolds a FreeBSD `Containerfile` and `.containerignore`
//! tailored for Legion (`docker.io/freebsd/freebsd-runtime:15.1` and
//! `docker.io/freebsd/freebsd-notoolchain:15.1`).

use std::path::{Path, PathBuf};

use clap::ValueEnum;

use crate::Error;

pub const DEFAULT_RELEASE: &str = "15.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Template {
    /// Rust project (`Cargo.toml`): multi-stage build into `freebsd-runtime`
    Rust,
    /// Go project (`go.mod`): multi-stage build into `freebsd-runtime`
    Go,
    /// Node.js project (`package.json`): `freebsd-notoolchain` with `node` + `npm`
    Node,
    /// Python project (`pyproject.toml` / `requirements.txt`): `freebsd-notoolchain` with `python3`
    Python,
    /// C/C++ project (`Makefile` / `CMakeLists.txt`): multi-stage build into `freebsd-runtime`
    C,
    /// FreeBSD package service (`freebsd-notoolchain` + `pkg install`)
    Pkg,
    /// Minimal static/prebuilt binary (`freebsd-runtime`)
    Runtime,
}

impl Template {
    pub fn as_str(self) -> &'static str {
        match self {
            Template::Rust => "rust",
            Template::Go => "go",
            Template::Node => "node",
            Template::Python => "python",
            Template::C => "c",
            Template::Pkg => "pkg",
            Template::Runtime => "runtime",
        }
    }
}

#[derive(Debug, Clone)]
pub struct InitOptions {
    pub dir: PathBuf,
    pub template: Option<Template>,
    pub release: Option<String>,
    pub name: Option<String>,
    pub force: bool,
}

#[derive(Debug, Clone)]
pub struct InitOutcome {
    pub containerfile: PathBuf,
    pub containerignore: Option<PathBuf>,
    pub template: Template,
    pub release: String,
    pub app_name: String,
}

/// Detects the FreeBSD release on the current host (e.g. `15.1` from
/// `15.1-RELEASE`), falling back to [`DEFAULT_RELEASE`].
pub fn detect_freebsd_release() -> String {
    if cfg!(target_os = "freebsd")
        && let Ok(out) = std::process::Command::new("freebsd-version")
            .arg("-u")
            .output()
        && out.status.success()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some((ver, _)) = text.trim().split_once('-')
            && !ver.is_empty()
        {
            return ver.to_owned();
        }
    }
    DEFAULT_RELEASE.to_owned()
}

/// Auto-detects the project template from files in `dir`.
pub fn detect_template(dir: &Path) -> Template {
    if dir.join("Cargo.toml").exists() {
        Template::Rust
    } else if dir.join("go.mod").exists() {
        Template::Go
    } else if dir.join("package.json").exists() {
        Template::Node
    } else if dir.join("pyproject.toml").exists() || dir.join("requirements.txt").exists() {
        Template::Python
    } else if dir.join("Makefile").exists()
        || dir.join("BSDMakefile").exists()
        || dir.join("CMakeLists.txt").exists()
    {
        Template::C
    } else {
        Template::Pkg
    }
}

/// Infers the binary/service name from `Cargo.toml`, `go.mod`, or the directory name.
pub fn detect_app_name(dir: &Path) -> String {
    if let Ok(cargo) = std::fs::read_to_string(dir.join("Cargo.toml")) {
        // The `name` in `[package]`, not a workspace's or a dependency's.
        let mut in_package = false;
        for line in cargo.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                in_package = t == "[package]";
                continue;
            }
            if in_package
                && let Some((key, val)) = t.split_once('=')
                && key.trim() == "name"
            {
                let name = val.trim().trim_matches('"').trim_matches('\'');
                if !name.is_empty() {
                    return name.to_owned();
                }
            }
        }
    }
    if let Ok(gomod) = std::fs::read_to_string(dir.join("go.mod")) {
        for line in gomod.lines() {
            if let Some(rest) = line.trim().strip_prefix("module ") {
                let last = rest.trim().rsplit('/').next().unwrap_or("");
                if !last.is_empty() {
                    return last.to_owned();
                }
            }
        }
    }
    dir.canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
        .or_else(|| dir.file_name().map(|s| s.to_string_lossy().into_owned()))
        .filter(|s| !s.is_empty() && s != ".")
        .unwrap_or_else(|| "app".to_owned())
}

pub fn scaffold(opts: &InitOptions) -> Result<InitOutcome, Error> {
    std::fs::create_dir_all(&opts.dir)?;
    let cf_path = opts.dir.join("Containerfile");
    if cf_path.exists() && !opts.force {
        return Err(Error::Build(format!(
            "{} already exists (pass --force to overwrite)",
            cf_path.display()
        )));
    }
    let template = opts.template.unwrap_or_else(|| detect_template(&opts.dir));
    let release = opts.release.clone().unwrap_or_else(detect_freebsd_release);
    let app_name = opts
        .name
        .clone()
        .unwrap_or_else(|| detect_app_name(&opts.dir));

    let content = render_containerfile(template, &release, &app_name);
    std::fs::write(&cf_path, content)?;

    // A `.containerignore` goes over a `.dockerignore`, whose rules are the
    // project's: one is not written over them, even with --force.
    let ignore_path = opts.dir.join(".containerignore");
    let wrote_ignore = if opts.dir.join(".dockerignore").exists() {
        None
    } else if !ignore_path.exists() || opts.force {
        std::fs::write(&ignore_path, render_containerignore(template))?;
        Some(ignore_path)
    } else {
        None
    };

    Ok(InitOutcome {
        containerfile: cf_path,
        containerignore: wrote_ignore,
        template,
        release,
        app_name,
    })
}

pub fn render_containerfile(template: Template, release: &str, app_name: &str) -> String {
    match template {
        Template::Rust => format!(
            r#"# Syntax: FreeBSD OCI image for Legion
FROM docker.io/freebsd/freebsd-notoolchain:{release} AS builder
RUN env ASSUME_ALWAYS_YES=yes pkg bootstrap -f >/dev/null \
 && env ASSUME_ALWAYS_YES=yes pkg install -y rust pkgconf >/dev/null \
 && pkg clean -ay >/dev/null && rm -rf /var/db/pkg/repos /var/cache/pkg/*
WORKDIR /src
COPY . .
RUN cargo build --release

FROM docker.io/freebsd/freebsd-runtime:{release}
COPY --from=builder /src/target/release/{app_name} /usr/local/bin/{app_name}
USER nobody
ENTRYPOINT ["/usr/local/bin/{app_name}"]
"#
        ),
        Template::Go => format!(
            r#"# Syntax: FreeBSD OCI image for Legion
FROM docker.io/freebsd/freebsd-notoolchain:{release} AS builder
RUN env ASSUME_ALWAYS_YES=yes pkg bootstrap -f >/dev/null \
 && env ASSUME_ALWAYS_YES=yes pkg install -y go >/dev/null \
 && pkg clean -ay >/dev/null && rm -rf /var/db/pkg/repos /var/cache/pkg/*
WORKDIR /src
COPY . .
RUN go build -o /out/{app_name} .

FROM docker.io/freebsd/freebsd-runtime:{release}
COPY --from=builder /out/{app_name} /usr/local/bin/{app_name}
USER nobody
ENTRYPOINT ["/usr/local/bin/{app_name}"]
"#
        ),
        Template::Node => format!(
            r#"# Syntax: FreeBSD OCI image for Legion
FROM docker.io/freebsd/freebsd-notoolchain:{release}
RUN env ASSUME_ALWAYS_YES=yes pkg bootstrap -f >/dev/null \
 && env ASSUME_ALWAYS_YES=yes pkg install -y node npm >/dev/null \
 && pkg clean -ay >/dev/null && rm -rf /var/db/pkg/repos /var/cache/pkg/*
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY . .
USER nobody
CMD ["/usr/local/bin/node", "index.js"]
"#
        ),
        Template::Python => format!(
            r#"# Syntax: FreeBSD OCI image for Legion
FROM docker.io/freebsd/freebsd-notoolchain:{release}
RUN env ASSUME_ALWAYS_YES=yes pkg bootstrap -f >/dev/null \
 && env ASSUME_ALWAYS_YES=yes pkg install -y python3 py311-pip >/dev/null \
 && pkg clean -ay >/dev/null && rm -rf /var/db/pkg/repos /var/cache/pkg/*
WORKDIR /app
COPY . .
USER nobody
CMD ["/usr/local/bin/python3", "-m", "{module}"]
"#,
            // A module's name has no hyphens: `my-app` is `my_app`.
            module = app_name.replace('-', "_")
        ),
        Template::C => format!(
            r#"# Syntax: FreeBSD OCI image for Legion
FROM docker.io/freebsd/freebsd-notoolchain:{release} AS builder
RUN env ASSUME_ALWAYS_YES=yes pkg bootstrap -f >/dev/null \
 && env ASSUME_ALWAYS_YES=yes pkg install -y llvm gmake pkgconf >/dev/null \
 && pkg clean -ay >/dev/null && rm -rf /var/db/pkg/repos /var/cache/pkg/*
WORKDIR /src
COPY . .
RUN make

FROM docker.io/freebsd/freebsd-runtime:{release}
COPY --from=builder /src/{app_name} /usr/local/bin/{app_name}
USER nobody
ENTRYPOINT ["/usr/local/bin/{app_name}"]
"#
        ),
        Template::Pkg => format!(
            r#"# Syntax: FreeBSD OCI image for Legion
FROM docker.io/freebsd/freebsd-notoolchain:{release}
RUN env ASSUME_ALWAYS_YES=yes pkg bootstrap -f >/dev/null \
 && env ASSUME_ALWAYS_YES=yes pkg install -y ca_root_nss >/dev/null \
 && pkg clean -ay >/dev/null && rm -rf /var/db/pkg/repos /var/cache/pkg/*
WORKDIR /app
COPY . /app
USER nobody
CMD ["/bin/sh"]
"#
        ),
        Template::Runtime => format!(
            r#"# Syntax: FreeBSD OCI image for Legion
FROM docker.io/freebsd/freebsd-runtime:{release}
COPY {app_name} /usr/local/bin/{app_name}
USER nobody
ENTRYPOINT ["/usr/local/bin/{app_name}"]
"#
        ),
    }
}

pub fn render_containerignore(template: Template) -> &'static str {
    match template {
        Template::Rust => ".git\ntarget\n*.tar\n",
        Template::Go => ".git\nbin\n*.tar\n",
        Template::Node => ".git\nnode_modules\nnpm-debug.log\n*.tar\n",
        Template::Python => ".git\n__pycache__\n.venv\n*.pyc\n*.tar\n",
        Template::C | Template::Pkg | Template::Runtime => ".git\n*.o\n*.tar\n",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_project_types_and_scaffolds() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(
            t.path().join("Cargo.toml"),
            "[package]\nname = \"demo-svc\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        assert_eq!(detect_template(t.path()), Template::Rust);
        assert_eq!(detect_app_name(t.path()), "demo-svc");
        let other = tempfile::tempdir().unwrap();
        std::fs::write(
            other.path().join("Cargo.toml"),
            "[workspace]\nmembers = []\n[workspace.package]\nname = \"ws\"\n[package]\nnamespace = \"x\"\nname = \"app\"\n",
        )
        .unwrap();
        assert_eq!(detect_app_name(other.path()), "app");

        let out = scaffold(&InitOptions {
            dir: t.path().to_path_buf(),
            template: None,
            release: Some("15.1".to_owned()),
            name: None,
            force: false,
        })
        .unwrap();
        assert_eq!(out.template, Template::Rust);
        let cf = std::fs::read_to_string(&out.containerfile).unwrap();
        assert!(cf.contains("FROM docker.io/freebsd/freebsd-runtime:15.1"));
        assert!(cf.contains("/usr/local/bin/demo-svc"));
        assert!(cf.contains("USER nobody"));
        assert!(out.containerignore.is_some());

        // A project's .dockerignore stays the rules: none goes over it.
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".dockerignore"), ".env\n").unwrap();
        let out = scaffold(&InitOptions {
            dir: d.path().to_path_buf(),
            template: None,
            release: Some("15.1".to_owned()),
            name: None,
            force: true,
        })
        .unwrap();
        assert!(out.containerignore.is_none());
        assert!(!d.path().join(".containerignore").exists());
    }
}
