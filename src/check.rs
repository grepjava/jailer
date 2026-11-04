//! Legion compatibility checks (`jailer check` and post-build lint):
//! validates `Containerfile` instructions, `ImageConfig`, and the image's
//! root file system (`/etc/passwd`, `/etc/group`, entrypoint executability,
//! stop signal, and `pkg` cache cleanup) against what Legion supports.

use std::path::Path;

use crate::containerfile::{Containerfile, Instruction, literal_word};
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

    /// Adds `other`'s findings but for codes already reported: an image's
    /// repeat what its Containerfile showed.
    pub fn merge(&mut self, other: CheckReport) {
        let seen: std::collections::HashSet<&str> = self.findings.iter().map(|f| f.code).collect();
        self.findings.extend(
            other
                .findings
                .into_iter()
                .filter(|f| !seen.contains(f.code)),
        );
    }
}

/// Whether a command in `text` runs pkg (or pkg-static) to `verb`, as
/// `pkg install`, `pkg -y install` or `/usr/sbin/pkg-static install` do.
fn runs_pkg(text: &str, verb: &str) -> bool {
    text.split(['&', ';', '|', '\n']).any(|command| {
        let mut words = command.split_whitespace();
        words
            .by_ref()
            .any(|w| matches!(w.rsplit('/').next(), Some("pkg" | "pkg-static")))
            && words.any(|w| w == verb)
    })
}

/// Checks a parsed `Containerfile` for settings Legion does not use or
/// FreeBSD image anti-patterns, in the stage built: `target`, or the last.
pub fn check_containerfile(cf: &Containerfile, target: Option<&str>) -> CheckReport {
    let mut report = CheckReport::default();
    let built = match target {
        Some(t) => cf.stages.iter().find(|s| s.name.as_deref() == Some(t)),
        None => cf.stages.last(),
    };
    let Some(final_stage) = built else {
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
            Instruction::Run(cmd, opts) => {
                let text = match cmd {
                    crate::containerfile::CommandForm::Shell(s) => s.clone(),
                    crate::containerfile::CommandForm::Exec(v) => v.join(" "),
                };
                // A cache mounted there keeps the packages out of the layer,
                // and cleaning would empty the cache.
                let cached = opts.mounts.iter().any(|m| {
                    matches!(m, crate::containerfile::RunMount::Cache { target, .. }
                        if target.trim_end_matches('/') == "/var/cache/pkg")
                });
                if runs_pkg(&text, "install") && !runs_pkg(&text, "clean") && !cached {
                    report.warn(
                        "LEGION002",
                        format!(
                            "line {}: `pkg install` without `pkg clean -ay && rm -rf /var/db/pkg/repos /var/cache/pkg/*` in the same RUN step leaves package caches in the layer",
                            sp.line
                        ),
                    );
                }
            }
            // One from a variable is checked in the image.
            Instruction::Stopsignal(sig)
                if !sig.contains('$') && state::signal(&literal_word(sig)).is_none() =>
            {
                let sig = literal_word(sig);
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
            if !program_exists_in_root(root, program, path_var, &config.config.working_dir) {
                report.error(
                    "LEGION009",
                    format!(
                        "command {program:?} was not found (or is not executable) in the image rootfs (PATH={path_var})"
                    ),
                );
            }
        }

        if !config.config.working_dir.is_empty() {
            // Links in it are followed inside the image, as the jail would.
            let wd = crate::build::resolve_in_jail(root, &config.config.working_dir, true);
            if !wd.is_ok_and(|wd| wd.is_dir()) {
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

/// Whether `program` runs in the image at `root`: found as execve(2) and
/// the shell find it, with relative paths from `work_dir`, and links
/// followed inside `root`.
fn program_exists_in_root(root: &Path, program: &str, path_var: &str, work_dir: &str) -> bool {
    let work_dir = if work_dir.is_empty() { "/" } else { work_dir };
    let from_work_dir = |p: &str| {
        if p.starts_with('/') {
            p.to_owned()
        } else {
            format!("{}/{p}", work_dir.trim_end_matches('/'))
        }
    };
    let candidates: Vec<String> = if program.contains('/') {
        vec![from_work_dir(program)]
    } else {
        path_var
            .split(':')
            .map(|d| from_work_dir(&format!("{}/{program}", if d.is_empty() { "." } else { d })))
            .collect()
    };
    for cand in candidates {
        let Ok(full) = crate::build::resolve_in_jail(root, &cand, true) else {
            continue;
        };
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
        let rep = check_containerfile(&cf, None);
        assert!(rep.has_errors());
        assert!(rep.findings.iter().any(|f| f.code == "LEGION001"));
        assert!(rep.findings.iter().any(|f| f.code == "LEGION003"));

        // A signal from a variable is the image's to check, and the image
        // does not repeat what the Containerfile reported.
        let cf = Containerfile::parse("FROM scratch\nARG SIG=SIGTERM\nSTOPSIGNAL $SIG\n").unwrap();
        assert!(!check_containerfile(&cf, None).has_errors());
        let cf = Containerfile::parse("FROM scratch\nSTOPSIGNAL SIGNOPE\n").unwrap();
        let mut both = check_containerfile(&cf, None);
        let mut cfg = ImageConfig::default();
        cfg.config.stop_signal = "SIGNOPE".to_owned();
        both.merge(check_image(&cfg, None));
        assert_eq!(
            both.findings
                .iter()
                .filter(|f| f.code == "LEGION003")
                .count(),
            1
        );

        // `pkg install` over a cache mount of /var/cache/pkg leaves nothing
        // to clean.
        let pkg = |run: &str| {
            let cf = Containerfile::parse(&format!("FROM scratch\n{run}\n")).unwrap();
            check_containerfile(&cf, None)
                .findings
                .iter()
                .any(|f| f.code == "LEGION002")
        };
        assert!(pkg("RUN pkg install -y curl"));
        assert!(pkg("RUN pkg -y install curl"));
        assert!(pkg("RUN /usr/sbin/pkg-static install -y curl && echo done"));
        assert!(!pkg("RUN pkg -y install curl && pkg clean -ay"));
        assert!(!pkg(
            "RUN --mount=type=cache,target=/var/cache/pkg pkg install -y curl"
        ));

        // With `--target`, the stage built is checked, not the last.
        let cf = Containerfile::parse(
            "FROM scratch AS app\nSTOPSIGNAL TERM\nFROM scratch AS unused\nSTOPSIGNAL INVALID\n",
        )
        .unwrap();
        assert!(check_containerfile(&cf, None).has_errors());
        assert!(!check_containerfile(&cf, Some("app")).has_errors());

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

        // Relative commands are found from the working directory.
        std::fs::create_dir_all(t.path().join("app")).unwrap();
        std::fs::copy(&sh, t.path().join("app/start")).unwrap();
        let relative = |cmd: &str, work_dir: &str| ImageConfig {
            config: Config {
                cmd: vec![cmd.to_owned()],
                working_dir: work_dir.to_owned(),
                ..good_cfg.config.clone()
            },
            ..good_cfg.clone()
        };
        let found = |cfg: &ImageConfig| !check_image(cfg, Some(t.path())).has_errors();
        assert!(found(&relative("./start", "/app")));
        assert!(found(&relative("app/start", "/")));
        assert!(!found(&relative("./start", "/")));
        assert!(found(&relative("../start", "/app/bin")));
        assert!(found(&relative("../../app/start", "/app")));
        let path_up = ImageConfig {
            config: Config {
                cmd: vec!["start".to_owned()],
                working_dir: "/app/bin".to_owned(),
                env: vec!["PATH=../:/bin".to_owned()],
                ..good_cfg.config.clone()
            },
            ..good_cfg.clone()
        };
        assert!(found(&path_up));
    }
}
