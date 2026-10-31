//! Legion compatibility checks (`jailer check` and post-build lint):
//! validates `Containerfile` instructions, `ImageConfig`, and the image's
//! root file system (`/etc/passwd`, `/etc/group`, entrypoint executability,
//! stop signal, and `pkg` cache cleanup) against what Legion supports.

use std::path::Path;

use crate::containerfile::{Containerfile, Instruction};
use crate::oci::ImageConfig;
use crate::{state, users};

/// The `PATH` a container's process gets when its image sets none.
const DEFAULT_PATH: &str = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct CheckReport {
    pub findings: Vec<Finding>,
}

impl CheckReport {
    pub fn warn(&mut self, code: &'static str, message: impl Into<String>) {
        self.findings.push(Finding {
            severity: Severity::Warning,
            code,
            message: message.into(),
        });
    }

    pub fn error(&mut self, code: &'static str, message: impl Into<String>) {
        self.findings.push(Finding {
            severity: Severity::Error,
            code,
            message: message.into(),
        });
    }

    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Error)
    }

    pub fn merge(&mut self, other: CheckReport) {
        self.findings.extend(other.findings);
    }
}

/// Checks a parsed `Containerfile` for settings Legion does not use or
/// FreeBSD image anti-patterns.
pub fn check_containerfile(cf: &Containerfile) -> CheckReport {
    let mut report = CheckReport::default();
    let Some(final_stage) = cf.stages.last() else {
        return report;
    };

    for sp in &final_stage.instructions {
        match &sp.instruction {
            Instruction::Healthcheck(hc) if !hc.eq_ignore_ascii_case("NONE") => {
                report.warn(
                    "LEGION001",
                    format!(
                        "line {}: HEALTHCHECK in Containerfile is ignored by Legion; configure pod probes or compose `healthcheck:` instead",
                        sp.line
                    ),
                );
            }
            Instruction::Run(cmd, _) => {
                let text = match cmd {
                    crate::containerfile::CommandForm::Shell(s) => s.clone(),
                    crate::containerfile::CommandForm::Exec(v) => v.join(" "),
                };
                if text.contains("pkg install") && !text.contains("pkg clean") {
                    report.warn(
                        "LEGION002",
                        format!(
                            "line {}: `pkg install` without `pkg clean -ay && rm -rf /var/db/pkg/repos /var/cache/pkg/*` in the same RUN step leaves package caches in the layer",
                            sp.line
                        ),
                    );
                }
            }
            Instruction::Stopsignal(sig) if state::signal(sig).is_none() => {
                report.error(
                    "LEGION003",
                    format!(
                        "line {}: STOPSIGNAL {sig:?} is not supported by Legion's jail runtime",
                        sp.line
                    ),
                );
            }
            _ => {}
        }
    }
    report
}

/// Checks an image's `ImageConfig` and optional extracted `rootfs` directory
/// against Legion's runtime requirements.
pub fn check_image(config: &ImageConfig, rootfs: Option<&Path>) -> CheckReport {
    let mut report = CheckReport::default();

    // 1. OS & architecture check
    match config.os.as_str() {
        "" | "freebsd" => {}
        "linux" => {
            report.warn(
                "LEGION004",
                "image targets `linux`; Legion nodes require `legion daemon --linux` and Linux ABI kernel modules to run it",
            );
        }
        other => {
            report.error(
                "LEGION005",
                format!("unsupported image OS {other:?}; Legion only runs `freebsd` (and `linux` with `--linux`)"),
            );
        }
    }

    match config.architecture.as_str() {
        "" | "amd64" | "arm64" => {}
        other => {
            report.warn(
                "LEGION006",
                format!("image architecture is {other:?}; Legion nodes target `amd64` and `arm64`"),
            );
        }
    }

    // 2. StopSignal check
    if !config.config.stop_signal.is_empty() && state::signal(&config.config.stop_signal).is_none()
    {
        report.error(
            "LEGION003",
            format!(
                "StopSignal {:?} is not recognized by Legion (use HUP, INT, QUIT, KILL, TERM, USR1, USR2, WINCH, PWR, or a signal number)",
                config.config.stop_signal
            ),
        );
    }

    // 3. Command check
    let argv: Vec<&str> = config
        .config
        .entrypoint
        .iter()
        .chain(&config.config.cmd)
        .map(String::as_str)
        .collect();
    if argv.is_empty() {
        report.warn(
            "LEGION007",
            "image defines neither Entrypoint nor Cmd; a Legion pod must specify `command` explicitly",
        );
    }

    // 4. Rootfs checks (if rootfs is available)
    if let Some(root) = rootfs {
        let passwd = std::fs::read_to_string(root.join("etc/passwd")).unwrap_or_default();
        let group = std::fs::read_to_string(root.join("etc/group")).unwrap_or_default();

        if let Err(e) = users::resolve(&config.config.user, &passwd, &group) {
            report.error(
                "LEGION008",
                format!(
                    "USER {:?} cannot be resolved in the image's /etc/passwd and /etc/group: {e}",
                    config.config.user
                ),
            );
        }

        if let Some(&program) = argv.first() {
            let path_var = config
                .config
                .env
                .iter()
                .find_map(|e| e.strip_prefix("PATH="))
                .unwrap_or(DEFAULT_PATH);
            if !program_exists_in_root(root, program, path_var) {
                report.error(
                    "LEGION009",
                    format!(
                        "command {program:?} was not found (or is not executable) in the image rootfs (PATH={path_var})"
                    ),
                );
            }
        }

        if !config.config.working_dir.is_empty() {
            let wd = root.join(config.config.working_dir.trim_start_matches('/'));
            if !wd.is_dir() {
                report.warn(
                    "LEGION010",
                    format!(
                        "WorkingDir {:?} does not exist in the image rootfs",
                        config.config.working_dir
                    ),
                );
            }
        }

        // Check for leftover FreeBSD pkg cache
        let cache_dir = root.join("var/cache/pkg");
        let repos_dir = root.join("var/db/pkg/repos");
        let has_cache = dir_non_empty(&cache_dir) || dir_non_empty(&repos_dir);
        if has_cache {
            report.warn(
                "LEGION002",
                "image contains leftover `/var/cache/pkg` or `/var/db/pkg/repos` data; clean them in the `RUN` step to keep pulls fast",
            );
        }
    }

    report
}

fn dir_non_empty(path: &Path) -> bool {
    std::fs::read_dir(path)
        .ok()
        .is_some_and(|mut it| it.next().is_some())
}

fn program_exists_in_root(root: &Path, program: &str, path_var: &str) -> bool {
    let candidates: Vec<String> = if program.contains('/') {
        vec![program.to_owned()]
    } else {
        path_var
            .split(':')
            .map(|d| format!("{}/{program}", if d.is_empty() { "." } else { d }))
            .collect()
    };
    for cand in candidates {
        let rel = cand.trim_start_matches('/');
        let full = root.join(rel);
        if let Ok(meta) = std::fs::metadata(&full)
            && meta.is_file()
        {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o111 != 0 {
                    return true;
                }
            }
            #[cfg(not(unix))]
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::Config;

    #[test]
    fn catches_missing_user_bad_signal_and_healthcheck() {
        let cf = Containerfile::parse(
            "FROM docker.io/freebsd/freebsd-runtime:15.1\nHEALTHCHECK CMD /bin/true\nSTOPSIGNAL SIGBAD\n",
        )
        .unwrap();
        let rep = check_containerfile(&cf);
        assert!(rep.has_errors());
        assert!(rep.findings.iter().any(|f| f.code == "LEGION001"));
        assert!(rep.findings.iter().any(|f| f.code == "LEGION003"));

        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("etc")).unwrap();
        std::fs::create_dir_all(t.path().join("bin")).unwrap();
        std::fs::write(
            t.path().join("etc/passwd"),
            "root:*:0:0:root:/root:/bin/sh\nnobody:*:65534:65534:Unprivileged:/nonexistent:/usr/sbin/nologin\n",
        )
        .unwrap();
        std::fs::write(
            t.path().join("etc/group"),
            "wheel:*:0:root\nnobody:*:65534:\n",
        )
        .unwrap();
        let sh = t.path().join("bin/sh");
        std::fs::write(&sh, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sh, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let good_cfg = ImageConfig {
            architecture: "amd64".to_owned(),
            os: "freebsd".to_owned(),
            config: Config {
                cmd: vec!["/bin/sh".to_owned()],
                user: "nobody".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        let r1 = check_image(&good_cfg, Some(t.path()));
        assert!(!r1.has_errors(), "{:?}", r1.findings);

        let bad_user_cfg = ImageConfig {
            config: Config {
                cmd: vec!["/bin/sh".to_owned()],
                user: "nonexistent".to_owned(),
                ..Default::default()
            },
            ..good_cfg.clone()
        };
        let r2 = check_image(&bad_user_cfg, Some(t.path()));
        assert!(r2.has_errors());
        assert!(r2.findings.iter().any(|f| f.code == "LEGION008"));
    }
}
