#![cfg(target_os = "freebsd")]

use std::path::Path;
use std::process::Command;

mod common;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Whether a qualification run asked for: there, what a test would skip
/// fails it instead, so that a pass means it ran.
fn must_run() -> bool {
    std::env::var_os("QUALIFY_REQUIRE_LIVE").is_some()
}

/// Whether `test` can run, which takes root.
fn live(test: &str) -> bool {
    if is_root() {
        return true;
    }
    assert!(!must_run(), "{test} requires root");
    println!("QUALIFY-SKIP: {test} requires root");
    false
}

#[test]
#[ignore = "needs root: scripts/jailer.qualify runs it"]
fn real_freebsd_jail_build_run_export_workflow() {
    if !live("real_freebsd_jail_build_run_export_workflow") {
        return;
    }

    let bin = env!("CARGO_BIN_EXE_jailer");
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().join("state");
    let project_dir = tmp.path().join("hello-service");
    std::fs::create_dir_all(&project_dir).unwrap();

    // A pool of the host's own: JAILER_TEST_POOL, zroot if unset.
    let pool = std::env::var("JAILER_TEST_POOL").unwrap_or_else(|_| "zroot".to_owned());
    let zfs_root = format!("{pool}/jailer-test-{}", std::process::id());

    // Ensure cleanup of test ZFS dataset on exit, and first of any container
    // a failed assertion left running, which would hold the dataset (and a
    // pod's epair, pf anchor and address).
    struct ZfsGuard(String, std::path::PathBuf);
    impl Drop for ZfsGuard {
        fn drop(&mut self) {
            let jailer = |args: &[&str]| {
                let state = self.1.join("state");
                let mut c = Command::new(env!("CARGO_BIN_EXE_jailer"));
                c.arg("--state-dir")
                    .arg(&state)
                    .args(["--zfs-root", &self.0]);
                c.args(args).output().ok()
            };
            if let Some(ps) = jailer(&["ps", "-a"]) {
                let ps = String::from_utf8_lossy(&ps.stdout);
                for id in ps
                    .lines()
                    .skip(1)
                    .filter_map(|l| l.split_whitespace().next())
                {
                    jailer(&["rm", "-f", id]);
                }
            }
            let _ = Command::new("zfs")
                .args(["destroy", "-r", &self.0])
                .status();
            let _ = jailer::layer::remove_tree(&self.1);
        }
    }
    let _guard = ZfsGuard(zfs_root.clone(), tmp.path().to_path_buf());

    // 1. Run `jailer init`
    let status = Command::new(bin)
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--zfs-root",
            &zfs_root,
            "init",
            "--template",
            "runtime",
            "--name",
            "hello-service",
            project_dir.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "jailer init failed");
    assert!(project_dir.join("Containerfile").exists());

    // Write a script and Containerfile that tests COPY + RUN in a real FreeBSD jail + USER nobody
    std::fs::write(
        project_dir.join("hello-service"),
        "#!/bin/sh\necho \"hello from $(whoami) in $(pwd): $* ($GREETING)\"\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            project_dir.join("hello-service"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    std::fs::write(
        project_dir.join("Containerfile"),
        r#"FROM docker.io/freebsd/freebsd-runtime:15.1
ENV GREETING=legion-ready
WORKDIR /app
COPY --chmod=0755 hello-service /usr/local/bin/hello-service
RUN /bin/sh -c "echo built-inside-jail > /app/stamp.txt"
RUN mkdir -p /usr/home && { [ -e /home ] || ln -s usr/home /home; }
WORKDIR /home/app
RUN /bin/sh -c "pwd > here.txt"
WORKDIR /app
USER nobody
ENTRYPOINT ["/usr/local/bin/hello-service"]
CMD ["default-arg"]
"#,
    )
    .unwrap();

    // 2. Run `jailer build`
    let build_out = Command::new(bin)
        .current_dir(&project_dir)
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--zfs-root",
            &zfs_root,
            "build",
            "--strict",
        ])
        .output()
        .unwrap();
    assert!(
        build_out.status.success(),
        "jailer build failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&build_out.stdout),
        String::from_utf8_lossy(&build_out.stderr)
    );

    // A rebuild reuses the RUN step's layer and yields the same image
    let rebuild_out = Command::new(bin)
        .current_dir(&project_dir)
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--zfs-root",
            &zfs_root,
            "build",
        ])
        .output()
        .unwrap();
    assert!(rebuild_out.status.success());
    let built_line = |out: &[u8]| {
        String::from_utf8_lossy(out)
            .lines()
            .find(|l| l.starts_with("Built "))
            .map(str::to_owned)
    };
    let rebuild_stdout = String::from_utf8_lossy(&rebuild_out.stdout);
    assert!(rebuild_stdout.contains("Using cache"), "{rebuild_stdout}");
    assert_eq!(
        built_line(&rebuild_out.stdout),
        built_line(&build_out.stdout)
    );

    // 3. Run `jailer run` in a real FreeBSD jail and verify stdout
    let run_out = Command::new(bin)
        .current_dir(&project_dir)
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--zfs-root",
            &zfs_root,
            "run",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&run_out.stdout);
    assert!(
        run_out.status.success(),
        "jailer run failed:\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run_out.stderr)
    );
    assert_eq!(
        stdout.trim(),
        "hello from nobody in /app: default-arg (legion-ready)"
    );

    // A squashed build runs the same, from one layer
    let squash_out = Command::new(bin)
        .current_dir(&project_dir)
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--zfs-root",
            &zfs_root,
            "build",
            "--squash",
            "-t",
            "flat:1",
        ])
        .output()
        .unwrap();
    assert!(
        squash_out.status.success(),
        "{}",
        String::from_utf8_lossy(&squash_out.stderr)
    );
    let flat_out = Command::new(bin)
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--zfs-root",
            &zfs_root,
            "run",
            "flat:1",
        ])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&flat_out.stdout), stdout);
    let flat_tar = tmp.path().join("flat.tar");
    let status = Command::new(bin)
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--zfs-root",
            &zfs_root,
            "export",
            "flat:1",
            flat_tar.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let manifest = Command::new("tar")
        .args(["xOf", flat_tar.to_str().unwrap(), "manifest.json"])
        .output()
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&manifest.stdout).unwrap();
    assert_eq!(manifest[0]["Layers"].as_array().unwrap().len(), 1);

    // Verify RUN step artifact `/app/stamp.txt` inside the built image
    let stamp_out = Command::new(bin)
        .current_dir(&project_dir)
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--zfs-root",
            &zfs_root,
            "run",
            "--entrypoint",
            "/bin/cat",
            "localhost/hello-service:latest",
            "/app/stamp.txt",
        ])
        .output()
        .unwrap();
    assert!(stamp_out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&stamp_out.stdout).trim(),
        "built-inside-jail"
    );

    // Containers as Legion runs them: detached, then ps, exec, logs, stop
    // and rm; Legion's security defaults, with --param over them; --vnet
    // as a pod with a member.
    let try_cmd = |args: &[&str]| {
        Command::new(bin)
            .args([
                "--state-dir",
                state_dir.to_str().unwrap(),
                "--zfs-root",
                &zfs_root,
            ])
            .args(args)
            .output()
            .unwrap()
    };
    let cmd = |args: &[&str]| {
        let out = try_cmd(args);
        assert!(
            out.status.success(),
            "jailer {args:?}:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let shell = [
        "--entrypoint",
        "/bin/sh",
        "localhost/hello-service:latest",
        "-c",
    ];
    let id = cmd(&[
        &["run", "-d", "--name", "bg"][..],
        &shell,
        &["echo up; sleep 60"],
    ]
    .concat());
    let id = id.trim();
    assert_eq!(id.len(), 64, "{id}");
    let ps = cmd(&["ps"]);
    assert!(ps.contains(" bg ") && ps.contains("running (jid "), "{ps}");
    assert_eq!(
        cmd(&[
            "exec",
            "bg",
            "/sbin/sysctl",
            "-n",
            "kern.securelevel",
            "security.jail.enforce_statfs"
        ]),
        "2\n2\n"
    );
    assert_eq!(cmd(&["logs", "bg"]), "up\n");
    cmd(&["stop", "-t", "1", &id[..12]]);
    assert!(cmd(&["ps", "-a"]).contains("exited"));
    cmd(&["rm", "bg"]);
    assert!(!cmd(&["ps", "-a"]).contains(" bg "));

    // `-d --rm`: removed once it exits, after this command has returned.
    cmd(&[
        &["run", "-d", "--rm", "--name", "gone"][..],
        &shell,
        &["sleep 2"],
    ]
    .concat());
    assert!(cmd(&["ps"]).contains(" gone "));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while cmd(&["ps", "-a"]).contains(" gone ") {
        assert!(
            std::time::Instant::now() < deadline,
            "run -d --rm left its container"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // `-d --network none`: the container is kept once it exits, and its
    // pod, a VNET jail with the container's name as hostname, stops.
    let pods = || {
        let out = Command::new("jls").arg("host.hostname").output().unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| *l == "quiet")
            .count()
    };
    cmd(&[
        &["run", "-d", "--network", "none", "--name", "quiet"][..],
        &shell,
        &["sleep 2"],
    ]
    .concat());
    assert!(pods() > 0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while pods() > 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "an exited -d --network none container kept its pod"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(cmd(&["ps", "-a"]).contains(" quiet "));
    cmd(&["rm", "quiet"]);

    let over = cmd(&[
        &["run", "--param", "securelevel=-1"][..],
        &shell,
        &["/sbin/sysctl -n kern.securelevel"],
    ]
    .concat());
    assert_eq!(over, "-1\n");

    let vnet = cmd(&[
        &["run", "--network", "none"][..],
        &shell,
        &["/sbin/ifconfig -l; /sbin/ifconfig lo0 inet | grep -c 'inet 127.0.0.1'"],
    ]
    .concat());
    assert_eq!(vnet, "lo0\n1\n");

    // --cpuset-cpus holds a container, and a build's RUN steps, to its CPUs.
    assert_eq!(
        cmd(&[&["run", "--cpuset-cpus", "0"][..], &shell, &["/bin/nproc"]].concat()),
        "1\n"
    );
    let cpus_dir = tmp.path().join("cpus");
    std::fs::create_dir_all(&cpus_dir).unwrap();
    std::fs::write(
        cpus_dir.join("Containerfile"),
        "FROM localhost/hello-service:latest\nUSER root\nRUN /bin/nproc > /cpus\n",
    )
    .unwrap();
    cmd(&[
        "build",
        "--cpuset-cpus",
        "0-1",
        "-t",
        "cpus:1",
        cpus_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        cmd(&["run", "--entrypoint", "/bin/cat", "cpus:1", "/cpus"]),
        "2\n"
    );

    // --vnet puts the pod on jailer's bridge; -p publishes its ports. Both
    // need pf.conf to call jailer's anchors.
    let host = |args: &[&str]| {
        let out = Command::new(args[0]).args(&args[1..]).output().unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    if host(&["pfctl", "-sn"]).contains("\"jailer/*\"") {
        // A listener: the host's nc and the libraries it needs.
        let nc_dir = tmp.path().join("nc");
        std::fs::create_dir_all(nc_dir.join("lib")).unwrap();
        std::fs::copy("/usr/bin/nc", nc_dir.join("nc")).unwrap();
        for lib in ["libipsec.so.4", "libsbuf.so.6", "libstats.so.0"] {
            std::fs::copy(Path::new("/lib").join(lib), nc_dir.join("lib").join(lib)).unwrap();
        }
        std::fs::write(
            nc_dir.join("Containerfile"),
            "FROM localhost/hello-service:latest\nCOPY nc /usr/bin/nc\nCOPY lib/ /lib/\n",
        )
        .unwrap();
        cmd(&["build", "-t", "nc:1", nc_dir.to_str().unwrap()]);
        cmd(&[
            "run",
            "-d",
            "--name",
            "web",
            "-p",
            // On the client's address alone: not every test host is private.
            "10.99.0.1:18080:8080",
            "--entrypoint",
            "/bin/sh",
            "nc:1",
            "-c",
            "echo hello | /usr/bin/nc -N -l 8080",
        ]);
        let ps = cmd(&["ps"]);
        assert!(
            ps.contains("10.77.0.") && ps.contains("18080:8080/tcp"),
            "{ps}"
        );
        let ip = ps
            .split_whitespace()
            .find(|w| w.starts_with("10.77.0."))
            .unwrap()
            .to_owned();
        // From outside: the host's own connections to its addresses go
        // through lo0, where pf cannot send them on. A client jail on an
        // epair of its own stands in for another machine.
        struct Client(String);
        impl Drop for Client {
            fn drop(&mut self) {
                let _ = Command::new("jail")
                    .args(["-r", "jailer_test_client"])
                    .status();
                let _ = Command::new("ifconfig").args([&self.0, "destroy"]).status();
            }
        }
        let a = host(&["ifconfig", "epair", "create"]).trim().to_owned();
        let _client = Client(a.clone());
        let b = format!("{}b", a.trim_end_matches('a'));
        host(&["ifconfig", &a, "inet", "10.99.0.1/30", "up"]);
        host(&[
            "jail",
            "-c",
            "name=jailer_test_client",
            "path=/",
            "vnet",
            "persist",
            &format!("vnet.interface={b}"),
        ]);
        let inside = |args: &[&str]| host(&[&["jexec", "jailer_test_client"][..], args].concat());
        inside(&["ifconfig", &b, "inet", "10.99.0.2/30", "up"]);
        inside(&["route", "add", "default", "10.99.0.1"]);
        let mut got = String::new();
        for _ in 0..20 {
            got = inside(&["nc", "-w", "2", "10.99.0.1", "18080"]);
            if !got.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        assert_eq!(got, "hello\n", "published port 18080, from outside");
        // Its command done, the container is kept and its pod lets go of
        // its address and port.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while Path::new("/var/run/jailer/net").join(&ip).exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "an exited -d container kept its address"
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(cmd(&["ps", "-a"]).contains(" web "));
        // And a pod reaches out, through the bridge and the host.
        let mut listener = Command::new("jexec")
            .args(["jailer_test_client", "sh", "-c", "echo hi | nc -N -l 9999"])
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert_eq!(
            cmd(&[
                "run",
                "--vnet",
                "--entrypoint",
                "/usr/bin/nc",
                "nc:1",
                "-w",
                "5",
                "10.99.0.2",
                "9999",
            ]),
            "hi\n"
        );
        listener.wait().unwrap();
        // Right after serving TCP: the jail may be dying still.
        cmd(&["rm", "-f", "web"]);
        assert!(
            !host(&["ifconfig", "-l"]).contains(" jp"),
            "epairs are gone"
        );
        assert!(!Path::new("/var/run/jailer/net").join(&ip).exists());
        for anchor in host(&["pfctl", "-a", "jailer", "-sA"]).split_whitespace() {
            let rules = host(&["pfctl", "-a", anchor, "-sn"]);
            assert!(!rules.contains("18080"), "{anchor}: {rules}");
        }
    } else {
        assert!(!must_run(), "pf.conf does not call jailer's anchors");
        let out = try_cmd(&[&["run", "--vnet"][..], &shell, &["true"]].concat());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && err.contains("rdr-anchor \"jailer/*\""),
            "{err}"
        );
    }

    // Resource limits are rctl rules on the container's jail, set before it
    // starts and dropped with it.
    let forks =
        "(for i in 1 2 3 4 5; do sleep 1 & done; wait) 2>/dev/null && echo free || echo limited";
    if Command::new("sysctl")
        .args(["-n", "kern.racct.enable"])
        .output()
        .map(|o| o.stdout == b"1\n")
        .unwrap_or(false)
    {
        assert_eq!(
            cmd(&[&["run", "--pids-limit", "3"][..], &shell, &[forks]].concat()),
            "limited\n"
        );
        assert_eq!(cmd(&[&["run"][..], &shell, &[forks]].concat()), "free\n");
        let id = cmd(&[
            &["run", "-d", "--name", "lim", "-m", "64m", "--cpus", "0.5"][..],
            &shell,
            &["sleep 60"],
        ]
        .concat());
        let rules = || String::from_utf8(Command::new("rctl").output().unwrap().stdout).unwrap();
        let set = rules();
        assert!(
            set.contains(&format!(
                "jail:{}:memoryuse:sigkill=67108864/process",
                id.trim()
            )) && set.contains(&format!("jail:{}:pcpu:deny=50", id.trim())),
            "{set}"
        );
        cmd(&["rm", "-f", "lim"]);
        assert!(
            !rules().contains(id.trim()),
            "the rules go with the container"
        );

        // And on a build's RUN steps.
        let lim_dir = tmp.path().join("limited");
        std::fs::create_dir_all(&lim_dir).unwrap();
        std::fs::write(
            lim_dir.join("Containerfile"),
            format!("FROM localhost/hello-service:latest\nUSER root\nRUN ({forks}) > /forks\n"),
        )
        .unwrap();
        cmd(&[
            "build",
            "--pids-limit",
            "3",
            "-t",
            "limited:1",
            lim_dir.to_str().unwrap(),
        ]);
        assert_eq!(
            cmd(&["run", "--entrypoint", "/bin/cat", "limited:1", "/forks"]),
            "limited\n"
        );
        assert!(
            !rules().contains("jailer_build_"),
            "no step's rules are left"
        );

        // Nor by a step that cannot start: a step before made its working
        // directory a loop of links.
        let loop_dir = tmp.path().join("looped");
        std::fs::create_dir_all(&loop_dir).unwrap();
        std::fs::write(
            loop_dir.join("Containerfile"),
            "FROM localhost/hello-service:latest\nUSER root\nWORKDIR /w\n\
             RUN cd / && rm -rf /w && ln -s w /w\nRUN true\n",
        )
        .unwrap();
        let failed = try_cmd(&[
            "build",
            "--pids-limit",
            "3",
            "-t",
            "looped:1",
            loop_dir.to_str().unwrap(),
        ]);
        assert!(
            String::from_utf8_lossy(&failed.stderr).contains("too many links"),
            "a looped WORKDIR fails the step: {}",
            String::from_utf8_lossy(&failed.stderr)
        );
        assert!(
            !rules().contains("jailer_build_"),
            "no rules are left by the step that failed:\n{}",
            rules()
        );
    }

    // COPY --from an image; file flags and hard links kept in layers;
    // jail parameters and SysV IPC for RUN steps.
    let flags_dir = tmp.path().join("flags");
    std::fs::create_dir_all(&flags_dir).unwrap();
    std::fs::write(
        flags_dir.join("Containerfile"),
        "FROM docker.io/freebsd/freebsd-runtime:15.1
COPY --from=localhost/hello-service:latest /app/stamp.txt /stamp-copy.txt
RUN echo x > /flagged && chflags schg /flagged && ln /bin/sh /bin/sh2 && /sbin/sysctl -n kern.securelevel > /securelevel
",
    )
    .unwrap();
    cmd(&[
        "build",
        "--param",
        "securelevel=1",
        "--sysv",
        "shm",
        "-t",
        "flags:1",
        flags_dir.to_str().unwrap(),
    ]);
    // The image has no stat(1).
    let seen = cmd(&[
        "run",
        "--entrypoint",
        "/bin/sh",
        "flags:1",
        "-c",
        "ls -lo /flagged; ls -i /bin/sh; ls -i /bin/sh2; cat /securelevel /stamp-copy.txt",
    ]);
    let lines: Vec<&str> = seen.lines().collect();
    assert_eq!(lines.len(), 5, "{seen}");
    assert!(lines[0].contains(" schg"), "{seen}");
    let inode = |l: &str| l.split_whitespace().next().unwrap().to_owned();
    assert_eq!(inode(lines[1]), inode(lines[2]), "{seen}");
    assert_eq!(lines[3..], ["1", "built-inside-jail"]);

    // COPY --from keeps a stage's or an image's flags and hard links.
    std::fs::write(
        flags_dir.join("Containerfile"),
        "FROM docker.io/freebsd/freebsd-runtime:15.1
ARG SRC=flags:1
COPY --from=$SRC /flagged /bin/sh /bin/sh2 /copied/
",
    )
    .unwrap();
    cmd(&["build", "-t", "copied:1", flags_dir.to_str().unwrap()]);
    let seen = cmd(&[
        "run",
        "--entrypoint",
        "/bin/sh",
        "copied:1",
        "-c",
        "ls -lo /copied/flagged; ls -i /copied/sh; ls -i /copied/sh2",
    ]);
    let lines: Vec<&str> = seen.lines().collect();
    assert_eq!(lines.len(), 3, "{seen}");
    assert!(lines[0].contains(" schg"), "{seen}");
    assert_eq!(inode(lines[1]), inode(lines[2]), "{seen}");
    assert_eq!(
        cmd(&["ps", "-a"]).lines().count(),
        1,
        "no pods or members are left"
    );

    // Stages are ZFS clones: of the base image, or of the stage before.
    std::fs::write(
        flags_dir.join("Containerfile"),
        "FROM docker.io/freebsd/freebsd-runtime:15.1 AS base
RUN echo one > /one && chflags schg /one
FROM base AS next
RUN echo two > /two
FROM next
RUN cat /one /two > /both
",
    )
    .unwrap();
    // In zstd layers, which a real jail's root is made from as well.
    cmd(&[
        "build",
        "--compression",
        "zstd",
        "-t",
        "staged:1",
        flags_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        cmd(&["run", "--entrypoint", "/bin/cat", "staged:1", "/both"]),
        "one\ntwo\n"
    );
    let left = Command::new("zfs")
        .args([
            "list",
            "-H",
            "-o",
            "name",
            "-r",
            &format!("{zfs_root}/build"),
        ])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&left.stdout).trim(),
        format!("{zfs_root}/build"),
        "a build's stage datasets go with it"
    );

    // A registry build cache: a build in another state directory takes
    // the RUN step from it instead of running it.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (addr, _registry) = common::start_mock_registry().await;
            tx.send(addr).unwrap();
            std::future::pending::<()>().await;
        })
    });
    let registry = format!("127.0.0.1:{}", rx.recv().unwrap().port());
    let cache_ref = format!("{registry}/me/cache:main");
    let cached_dir = tmp.path().join("cached");
    std::fs::create_dir_all(&cached_dir).unwrap();
    std::fs::write(
        cached_dir.join("Containerfile"),
        "FROM docker.io/freebsd/freebsd-runtime:15.1\nRUN /bin/uuidgen > /id\n",
    )
    .unwrap();
    cmd(&[
        "--plain-http",
        &registry,
        "build",
        "--cache-to",
        &cache_ref,
        "-t",
        "cached:1",
        cached_dir.to_str().unwrap(),
    ]);
    let other_state = tmp.path().join("other-state");
    let other_zfs = format!("{zfs_root}/other");
    let other = |args: &[&str]| {
        let out = Command::new(bin)
            .args([
                "--state-dir",
                other_state.to_str().unwrap(),
                "--zfs-root",
                &other_zfs,
                "--plain-http",
                &registry,
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "jailer {args:?}:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let built = other(&[
        "build",
        "--cache-from",
        &cache_ref,
        "-t",
        "cached:1",
        cached_dir.to_str().unwrap(),
    ]);
    assert!(built.contains("From the registry cache"), "{built}");
    let id = |run: &dyn Fn(&[&str]) -> String| {
        run(&["run", "--entrypoint", "/bin/cat", "cached:1", "/id"])
    };
    assert_eq!(id(&other), id(&cmd));

    // 4. Run `jailer export app.tar`
    let archive = tmp.path().join("app.tar");
    let export_out = Command::new(bin)
        .current_dir(&project_dir)
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--zfs-root",
            &zfs_root,
            "export",
            archive.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        export_out.status.success(),
        "jailer export failed: {}",
        String::from_utf8_lossy(&export_out.stderr)
    );
    assert!(Path::new(&archive).exists());

    // 5. Run `jailer check`
    let check_out = Command::new(bin)
        .current_dir(&project_dir)
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--zfs-root",
            &zfs_root,
            "check",
        ])
        .output()
        .unwrap();
    assert!(
        check_out.status.success(),
        "jailer check failed: {}",
        String::from_utf8_lossy(&check_out.stderr)
    );
}

#[test]
#[ignore = "needs root: scripts/jailer.qualify runs it"]
fn run_mounts_reach_the_step_but_not_the_image() {
    if !live("run_mounts_reach_the_step_but_not_the_image") {
        return;
    }
    let bin = env!("CARGO_BIN_EXE_jailer");
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    let ctx = tmp.path().join("ctx");
    std::fs::create_dir_all(ctx.join("data")).unwrap();
    std::fs::write(ctx.join("data/a.txt"), "original\n").unwrap();
    std::fs::write(ctx.join("data/hidden.txt"), "ignored\n").unwrap();
    std::fs::write(ctx.join(".containerignore"), "data/hidden.txt\n").unwrap();
    std::fs::write(ctx.join("tok.txt"), "s3cr3t-value").unwrap();
    std::fs::write(
        ctx.join("Containerfile"),
        r#"# syntax=docker/dockerfile:1
FROM docker.io/freebsd/freebsd-runtime:15.1
RUN --mount=type=cache,target=/var/cache/thing sh -c 'echo run >> /var/cache/thing/log; n=0; while read l; do n=$((n+1)); done < /var/cache/thing/log; echo $n > /count'
RUN --mount=type=bind,source=data,target=/data,rw sh -c 'cat /data/a.txt > /bound; echo scribble > /data/a.txt'
RUN --mount=type=secret,id=tok sh -c 'v=$(cat /run/secrets/tok); echo ${#v} > /secretlen'
RUN --mount=type=tmpfs,target=/scratch sh -c 'df -t tmpfs /scratch >/dev/null && echo yes > /tmpfs'
RUN --network=none sh -c 'ifconfig -l > /ifs'
RUN --mount=type=ssh sh -c 'test -S "$SSH_AUTH_SOCK" && echo "$SSH_AUTH_SOCK" > /ssh'
RUN --mount=type=ssh,target=/etc/agent.sock sh -c 'test -S /etc/agent.sock && test -s /etc/passwd && echo kept > /etcssh'
RUN --mount=type=ssh,target=/run/buildkit/a.sock --mount=type=ssh,target=/run/buildkit/b.sock sh -c 'test -S /run/buildkit/a.sock && test -S /run/buildkit/b.sock'
RUN --mount=type=bind,target=/ctx ls /ctx/data > /ctxls
RUN --mount=type=bind,from=docker.io/freebsd/freebsd-runtime:15.1,source=/bin,target=/img test -x /img/sh && echo yes > /fromimg
RUN <<EOF
echo heredoc-$((1+1)) > /hd
EOF
RUN <<EOF
#!/bin/sh -e
echo shebang > /sb
EOF
RUN cat <<A > /two && cat <<'B' >> /two
x-$((2+3))
A
y-$((2+3))
B
CMD ["/bin/sh", "-c", "for f in count bound secretlen tmpfs ifs ctxls fromimg hd sb ssh etcssh two; do printf '%s=%s ' $f $(cat /$f); done; for d in /var/cache/thing /data /run/secrets /scratch /ctx /img /run/buildkit /etc/agent.sock; do test -e $d && printf 'leaked=%s ' $d; done; echo"]
"#,
    )
    .unwrap();

    let jailer = |args: &[&str]| {
        let out = Command::new(bin)
            .current_dir(&ctx)
            .args(["--state-dir", state.to_str().unwrap(), "--no-zfs"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "jailer {args:?}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = jailer::layer::remove_tree(&self.0);
        }
    }
    let _cleanup = Cleanup(tmp.path().to_path_buf());

    // An SSH agent for `--mount=type=ssh`
    let agent_sock = tmp.path().join("agent.sock");
    struct Agent(std::process::Child);
    impl Drop for Agent {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _agent = Agent(
        Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&agent_sock)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    while !agent_sock.exists() {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let ssh_arg = format!("default={}", agent_sock.display());

    let build = [
        "build",
        "--no-cache",
        "--secret",
        "id=tok,src=tok.txt",
        "--ssh",
        &ssh_arg,
        "-t",
        "m:1",
        ".",
    ];
    jailer(&build);
    assert_eq!(
        jailer(&["run", "m:1"]),
        "count=1 bound=original secretlen=12 tmpfs=yes ifs=lo0 ctxls=a.txt fromimg=yes hd=heredoc-2 sb=shebang ssh=/run/buildkit/ssh_agent.0 etcssh=kept two=x-5 y-$((2+3))="
    );
    // The cache mount keeps its contents; the rw bind left the context alone.
    jailer(&build);
    assert!(jailer(&["run", "m:1"]).starts_with("count=2 "));
    assert_eq!(
        std::fs::read_to_string(ctx.join("data/a.txt")).unwrap(),
        "original\n"
    );
    // The secret's value is in no layer.
    jailer(&["export", "m:1", tmp.path().join("m.tar").to_str().unwrap()]);
    let layers = Command::new("sh")
        .arg("-c")
        .arg("mkdir x && tar xf m.tar -C x && for l in x/blobs/sha256/*; do tar xzf $l -O 2>/dev/null; done")
        .current_dir(tmp.path())
        .output()
        .unwrap()
        .stdout;
    assert!(!String::from_utf8_lossy(&layers).contains("s3cr3t-value"));

    // A step that puts a link in place of the directory made for its agent
    // does not take what is removed after it out to the host's files.
    let host = tmp.path().join("host");
    std::fs::create_dir_all(host.join("z")).unwrap();
    let _host_sock = std::os::unix::net::UnixListener::bind(host.join("z/c.sock")).unwrap();
    std::fs::write(
        ctx.join("Containerfile.links"),
        format!(
            "FROM docker.io/freebsd/freebsd-runtime:15.1\n\
             RUN --mount=type=ssh,target=/run/y/z/c.sock sh -c 'rm -rf /run/y && ln -s {} /run/y'\n",
            host.display()
        ),
    )
    .unwrap();
    jailer(&[
        "build",
        "--no-cache",
        "--ssh",
        &ssh_arg,
        "-f",
        "Containerfile.links",
        "-t",
        "links:1",
        ".",
    ]);
    assert!(
        std::fs::symlink_metadata(host.join("z/c.sock")).is_ok(),
        "the host's socket is still there"
    );

    // A directory .containerignore leaves out, with a file put back, mounts
    // with that file; the mode of a mounted directory and the size of a
    // tmpfs are in the steps' keys.
    let ctx2 = tmp.path().join("ctx2");
    std::fs::create_dir_all(ctx2.join("docs")).unwrap();
    std::fs::create_dir_all(ctx2.join("m")).unwrap();
    std::fs::write(ctx2.join("docs/keep.txt"), "k").unwrap();
    std::fs::write(ctx2.join("docs/drop.txt"), "d").unwrap();
    std::fs::write(ctx2.join(".containerignore"), "docs\n!docs/keep.txt\n").unwrap();
    let mounts_cf = |size: &str| {
        std::fs::write(
            ctx2.join("Containerfile"),
            format!(
                "FROM docker.io/freebsd/freebsd-runtime:15.1\n\
                 RUN --mount=type=bind,source=docs,target=/d ls /d > /docs\n\
                 RUN --mount=type=tmpfs,target=/t,size={size} df -k /t > /size\n\
                 RUN --mount=type=bind,source=m,target=/m ls -ld /m > /mode\n\
                 CMD [\"/bin/cat\", \"/docs\", \"/mode\", \"/size\"]\n"
            ),
        )
        .unwrap();
    };
    let seen = || {
        jailer(&["build", "-t", "k:1", ctx2.to_str().unwrap()]);
        let out = jailer(&["run", "k:1"]);
        let lines: Vec<&str> = out.lines().collect();
        let mode = lines[1].split_whitespace().next().unwrap().to_owned();
        let blocks = lines
            .last()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned();
        (lines[0].to_owned(), mode, blocks)
    };
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(ctx2.join("m"), std::fs::Permissions::from_mode(0o755)).unwrap();
    // One change at a time, each to a step after which nothing else would
    // run again anyway.
    mounts_cf("1m");
    assert_eq!(
        seen(),
        ("keep.txt".into(), "drwxr-xr-x".into(), "1024".into())
    );
    mounts_cf("2m");
    assert_eq!(
        seen(),
        ("keep.txt".into(), "drwxr-xr-x".into(), "2048".into())
    );
    std::fs::set_permissions(ctx2.join("m"), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        seen(),
        ("keep.txt".into(), "drwx------".into(), "2048".into())
    );
}

#[test]
#[ignore = "needs root: scripts/jailer.qualify runs it"]
fn cached_steps_follow_the_layer_before_them_and_chown_keeps_setuid() {
    if !live("cached_steps_follow_the_layer_before_them_and_chown_keeps_setuid") {
        return;
    }
    let bin = env!("CARGO_BIN_EXE_jailer");
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    let ctx = tmp.path().join("ctx");
    let other = tmp.path().join("other");
    std::fs::create_dir_all(&ctx).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(ctx.join("tool"), "#!/bin/sh\n").unwrap();
    // The first step makes /v empty, and from then on not; the second makes
    // nothing while /v is empty.
    std::fs::write(
        ctx.join("Containerfile"),
        r#"FROM docker.io/freebsd/freebsd-runtime:15.1
RUN --mount=type=cache,target=/c sh -c 'cat /c/n > /v 2>/dev/null; echo x >> /c/n'
RUN sh -c 'if test -s /v; then : > /nonempty; fi'
COPY --chown=nobody:nobody --chmod=4755 tool /tool
CMD ["/bin/sh", "-c", "set -- $(ls -l /tool); echo $1 $3:$4; test -e /nonempty && echo nonempty || echo empty"]
"#,
    )
    .unwrap();
    std::fs::write(
        other.join("Containerfile"),
        "FROM docker.io/freebsd/freebsd-runtime:15.1\nLABEL other=1\n",
    )
    .unwrap();
    let jailer = |args: &[&str]| {
        let out = Command::new(bin)
            .args(["--state-dir", state.to_str().unwrap(), "--no-zfs"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "jailer {args:?}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = jailer::layer::remove_tree(&self.0);
        }
    }
    let _cleanup = Cleanup(tmp.path().to_path_buf());

    let ctx_arg = ctx.to_str().unwrap();
    jailer(&["build", "-t", "c:1", ctx_arg]);
    assert_eq!(jailer(&["run", "c:1"]), "-rwsr-xr-x nobody:nobody\nempty");
    // Without the image, a trim drops the first step's layer from the
    // cache; the second step, which made nothing, keeps its entry.
    jailer(&["rmi", "c:1"]);
    jailer(&[
        "build",
        "--cache-max",
        "0",
        "-t",
        "o:1",
        other.to_str().unwrap(),
    ]);
    // Run again, the first step makes another /v: the second must run too.
    jailer(&["build", "-t", "c:2", ctx_arg]);
    assert_eq!(
        jailer(&["run", "c:2"]),
        "-rwsr-xr-x nobody:nobody\nnonempty"
    );
}

#[test]
#[ignore = "needs root: scripts/jailer.qualify runs it"]
fn stage_copies_keep_owners_archives_take_flags_and_cache_options_count() {
    if !live("stage_copies_keep_owners_archives_take_flags_and_cache_options_count") {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let bin = env!("CARGO_BIN_EXE_jailer");
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    let ctx = tmp.path().join("ctx");
    let packed = tmp.path().join("packed");
    std::fs::create_dir_all(ctx.join("d")).unwrap();
    std::fs::create_dir_all(&packed).unwrap();
    let mode = |p: &std::path::Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    };
    std::fs::write(ctx.join("f"), "f\n").unwrap();
    std::fs::write(ctx.join("d/g"), "g\n").unwrap();
    std::fs::write(packed.join("t"), "#!/bin/sh\n").unwrap();
    mode(&ctx.join("d"), 0o755);
    mode(&ctx.join("d/g"), 0o644);
    mode(&packed.join("t"), 0o644);
    let tar = Command::new("tar")
        .arg("-cf")
        .arg(ctx.join("a.tar"))
        .arg("-C")
        .arg(&packed)
        .arg("t")
        .status()
        .unwrap();
    assert!(tar.success());
    // A named pipe, which a copy makes again rather than reads.
    let fifo = Command::new("mkfifo")
        .arg(ctx.join("queue"))
        .status()
        .unwrap();
    assert!(fifo.success());
    let containerfile = |cache_opts: &str| {
        std::fs::write(
            ctx.join("Containerfile"),
            format!(
                r#"FROM docker.io/freebsd/freebsd-runtime:15.1 AS base
COPY --chown=nobody:nobody --chmod=0640 f /owned
COPY --chown=nobody:nobody d /d
COPY queue /queue
FROM docker.io/freebsd/freebsd-runtime:15.1
COPY --from=base /owned /owned
COPY --from=base /d /d
COPY --from=base /queue /queue
ARG ID=c
ADD --chown=nobody:nobody --chmod=4755 a.tar /arc/
RUN --mount=type=cache,id=$ID,target=/c,sharing=locked{cache_opts} --mount=type=cache,id=$ID,target=/c2,sharing=locked sh -c 'if (: > /c/x) 2>/dev/null; then echo w; else echo ro; fi > /rc'
CMD ["/bin/sh", "-c", "for f in /owned /d /d/g /arc/t; do set -- $(ls -ld $f); echo $1 $3:$4; done; test -p /queue && echo pipe; cat /rc"]
"#
            ),
        )
        .unwrap();
    };
    let jailer = |args: &[&str]| {
        let out = Command::new(bin)
            .args(["--state-dir", state.to_str().unwrap(), "--no-zfs"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "jailer {args:?}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = jailer::layer::remove_tree(&self.0);
        }
    }
    let _cleanup = Cleanup(tmp.path().to_path_buf());

    let ctx_arg = ctx.to_str().unwrap();
    let owners = "-rw-r----- nobody:nobody\n\
                  drwxr-xr-x nobody:nobody\n\
                  -rw-r--r-- nobody:nobody\n\
                  -rwsr-xr-x nobody:nobody";
    containerfile("");
    jailer(&["build", "-t", "o:1", ctx_arg]);
    assert_eq!(jailer(&["run", "o:1"]), format!("{owners}\npipe\nw"));
    // A read-only cache is another step: it runs again, and cannot write.
    containerfile(",ro");
    jailer(&["build", "-t", "o:2", ctx_arg]);
    assert_eq!(jailer(&["run", "o:2"]), format!("{owners}\npipe\nro"));
}

#[test]
#[ignore = "needs root: scripts/jailer.qualify runs it"]
fn the_pods_hostname_wins_and_a_stop_ends_an_attached_run() {
    if !live("the_pods_hostname_wins_and_a_stop_ends_an_attached_run") {
        return;
    }
    let bin = env!("CARGO_BIN_EXE_jailer");
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    let ctx = tmp.path().join("ctx");
    std::fs::create_dir_all(&ctx).unwrap();
    std::fs::write(
        ctx.join("Containerfile"),
        "FROM docker.io/freebsd/freebsd-runtime:15.1\nENV HOSTNAME=from-image\n",
    )
    .unwrap();
    let jailer = || {
        let mut c = Command::new(bin);
        c.args(["--state-dir", state.to_str().unwrap(), "--no-zfs"]);
        c
    };
    let ok = |args: &[&str]| {
        let out = jailer().args(args).output().unwrap();
        assert!(
            out.status.success(),
            "jailer {args:?}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    // Ends a run a failed assertion left attached, then its files.
    struct Cleanup(std::path::PathBuf, Option<std::process::Child>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(mut run) = self.1.take() {
                let _ = run.kill();
                let _ = run.wait();
            }
            let _ = Command::new(env!("CARGO_BIN_EXE_jailer"))
                .arg("--state-dir")
                .arg(self.0.join("state"))
                .args(["--no-zfs", "rm", "-f", "attached"])
                .output();
            let _ = jailer::layer::remove_tree(&self.0);
        }
    }
    let mut cleanup = Cleanup(tmp.path().to_path_buf(), None);

    ok(&["build", "-t", "h:1", ctx.to_str().unwrap()]);

    // Run without a shell, which would hide a duplicate.
    let env = ok(&[
        "run",
        "--hostname",
        "the-pod",
        "--entrypoint",
        "/usr/bin/env",
        "h:1",
    ]);
    let names: Vec<_> = env.lines().filter(|l| l.starts_with("HOSTNAME=")).collect();
    assert_eq!(names, ["HOSTNAME=the-pod"], "{env}");

    let run = jailer()
        .args([
            "run",
            "--rm",
            "--name",
            "attached",
            "--entrypoint",
            "/bin/sleep",
            "h:1",
            "300",
        ])
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();
    cleanup.1 = Some(run);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !ok(&["ps"]).contains("attached") {
        assert!(std::time::Instant::now() < deadline, "never started");
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // The container goes at once: no waiting out the stop's 10 seconds.
    let asked = std::time::Instant::now();
    ok(&["stop", "attached"]);
    assert!(asked.elapsed().as_secs() < 9, "{:?}", asked.elapsed());

    // `run` lives to report the exit and remove the container.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        if let Some(status) = cleanup.1.as_mut().unwrap().try_wait().unwrap() {
            break status;
        }
        assert!(std::time::Instant::now() < deadline, "run never returned");
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    cleanup.1 = None;
    assert_eq!(status.code(), Some(143), "{status:?}");
    let all = ok(&["ps", "-a"]);
    assert!(!all.contains("attached"), "{all}");
}

#[test]
#[ignore = "needs root: scripts/jailer.qualify runs it"]
fn a_signal_to_exec_ends_its_command() {
    if !live("a_signal_to_exec_ends_its_command") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    let ctx = tmp.path().join("ctx");
    std::fs::create_dir_all(&ctx).unwrap();
    std::fs::write(
        ctx.join("Containerfile"),
        "FROM docker.io/freebsd/freebsd-runtime:15.1\n",
    )
    .unwrap();
    let jailer = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_jailer"));
        c.args(["--state-dir", state.to_str().unwrap(), "--no-zfs"]);
        c
    };
    let ok = |args: &[&str]| {
        let out = jailer().args(args).output().unwrap();
        assert!(
            out.status.success(),
            "jailer {args:?}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = Command::new(env!("CARGO_BIN_EXE_jailer"))
                .arg("--state-dir")
                .arg(self.0.join("state"))
                .args(["--no-zfs", "rm", "-f", "held"])
                .output();
            let _ = jailer::layer::remove_tree(&self.0);
        }
    }
    let _cleanup = Cleanup(tmp.path().to_path_buf());
    ok(&["build", "-t", "e:1", ctx.to_str().unwrap()]);
    let entry = ["--entrypoint", "/bin/sleep", "e:1"];
    ok(&[&["run", "-d", "--name", "held"][..], &entry, &["300"]].concat());

    // The command itself, not the jailer or shim naming it.
    let running = |seconds: &str| {
        Command::new("pgrep")
            .args(["-f", &format!("^/bin/sleep {seconds}$")])
            .status()
            .unwrap()
            .success()
    };
    let wait_for = |what: &str, done: &mut dyn FnMut() -> bool| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !done() {
            assert!(std::time::Instant::now() < deadline, "{what}");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    };
    for (signal, seconds) in [(libc::SIGINT, "7701"), (libc::SIGTERM, "7702")] {
        let mut exec = jailer()
            .args(["exec", "held", "/bin/sleep", seconds])
            .spawn()
            .unwrap();
        wait_for("never started", &mut || running(seconds));
        unsafe { libc::kill(exec.id() as i32, signal) };
        let status = exec.wait().unwrap();
        wait_for("left running in the jail", &mut || !running(seconds));
        assert_eq!(status.code(), Some(128 + signal), "{status:?}");
    }

    // On a terminal, Ctrl-C is the command's: this one catches it and goes
    // on, with its terminal, to its own exit. script(1) makes the terminal,
    // and a byte written to it the keypress.
    let out = tmp.path().join("out");
    let mut terminal = Command::new("script")
        .args(["-q", "/dev/null", env!("CARGO_BIN_EXE_jailer")])
        .args(["--state-dir", state.to_str().unwrap(), "--no-zfs"])
        .args(["exec", "-t", "held", "/bin/sh", "-c"])
        .arg("trap 'echo caught' INT; /bin/sleep 7703; echo done; exit 5")
        .stdin(std::process::Stdio::piped())
        .stdout(std::fs::File::create(&out).unwrap())
        .spawn()
        .unwrap();
    wait_for("never started", &mut || running("7703"));
    let mut keys = terminal.stdin.take().unwrap();
    std::io::Write::write_all(&mut keys, b"").unwrap();
    let status = terminal.wait().unwrap();
    let said = std::fs::read_to_string(&out).unwrap();
    assert!(said.contains("caught") && said.contains("done"), "{said}");
    assert_eq!(
        status.code(),
        Some(5),
        "{status:?}
{said}"
    );
    drop(keys);
}

#[test]
#[ignore = "needs root: scripts/jailer.qualify runs it"]
fn interrupted_builds_and_runs_leave_nothing() {
    use std::os::unix::process::CommandExt;
    if !live("interrupted_builds_and_runs_leave_nothing") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    let base = tmp.path().join("base");
    let step = tmp.path().join("step");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::create_dir_all(&step).unwrap();
    std::fs::write(
        base.join("Containerfile"),
        "FROM docker.io/freebsd/freebsd-runtime:15.1\n",
    )
    .unwrap();
    std::fs::write(
        step.join("Containerfile"),
        "FROM localhost/i:1\nRUN /bin/sleep 7721\n",
    )
    .unwrap();
    let jailer = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_jailer"));
        c.args(["--state-dir", state.to_str().unwrap(), "--no-zfs"]);
        c
    };
    let ok = |args: &[&str]| {
        let out = jailer().args(args).output().unwrap();
        assert!(
            out.status.success(),
            "jailer {args:?}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    fn jails(under: &Path) -> Vec<String> {
        let out = Command::new("jls").args(["name", "path"]).output().unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_once(' '))
            .filter(|(_, path)| path.starts_with(under.to_str().unwrap()))
            .map(|(name, _)| name.to_owned())
            .collect()
    }
    fn mounts(under: &Path) -> Vec<String> {
        let out = Command::new("mount").arg("-p").output().unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_whitespace().nth(1))
            .filter(|at| at.starts_with(under.to_str().unwrap()))
            .map(str::to_owned)
            .collect()
    }
    // After a failed assertion: jails first, then what they held.
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for jail in jails(&self.0) {
                let _ = Command::new("rctl")
                    .arg("-r")
                    .arg(format!("jail:{jail}:"))
                    .output();
                let _ = Command::new("jail").args(["-r", &jail]).output();
            }
            for mount in mounts(&self.0).iter().rev() {
                let _ = Command::new("umount").args(["-f", mount]).output();
            }
            let _ = jailer::layer::remove_tree(&self.0);
        }
    }
    let _cleanup = Cleanup(tmp.path().to_path_buf());
    let wait_for = |what: &str, done: &mut dyn FnMut() -> bool| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !done() {
            assert!(std::time::Instant::now() < deadline, "{what}");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    };
    let running = |seconds: &str| {
        Command::new("pgrep")
            .args(["-f", &format!("^/bin/sleep {seconds}$")])
            .status()
            .unwrap()
            .success()
    };
    let rules = || {
        let out = Command::new("rctl").output().unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    ok(&["build", "-t", "i:1", base.to_str().unwrap()]);

    // Ctrl-C, as a terminal sends it: to the whole group. The step goes,
    // with its jail, mounts and limits, and so does the build.
    let mut build = jailer()
        .args(["build", "--pids-limit", "50", "-t", "s:1"])
        .arg(&step)
        .process_group(0)
        .spawn()
        .unwrap();
    wait_for("the step never started", &mut || running("7721"));
    let jail = jails(tmp.path()).pop().unwrap();
    assert!(rules().contains(&jail), "{}", rules());
    unsafe { libc::kill(-(build.id() as i32), libc::SIGINT) };
    let status = build.wait().unwrap();
    assert_eq!(status.code(), Some(130), "{status:?}");
    assert_eq!(jails(tmp.path()), Vec::<String>::new());
    assert_eq!(mounts(tmp.path()), Vec::<String>::new());
    assert!(!rules().contains(&jail), "{}", rules());

    // `run --rm` outlives its command to remove it: when Ctrl-C ends the
    // command, when the command takes it and ends as it likes, and when a
    // signal comes for `run` alone.
    for (seconds, script, to, signal, code) in [
        ("7722", "exec /bin/sleep 7722", -1, libc::SIGINT, 130),
        (
            "7723",
            "trap 'exit 5' INT; /bin/sleep 7723 & wait",
            -1,
            libc::SIGINT,
            5,
        ),
        ("7724", "exec /bin/sleep 7724", 1, libc::SIGTERM, 143),
    ] {
        let mut run = jailer()
            .args(["run", "--rm", "--name", "gone", "--entrypoint", "/bin/sh"])
            .args(["i:1", "-c", script])
            .process_group(0)
            .spawn()
            .unwrap();
        wait_for("the command never started", &mut || running(seconds));
        unsafe { libc::kill(to * run.id() as i32, signal) };
        let status = run.wait().unwrap();
        assert_eq!(status.code(), Some(code), "{script}: {status:?}");
        let all = ok(&["ps", "-a"]);
        assert!(!all.contains("gone"), "{script}: {all}");
        assert_eq!(jails(tmp.path()), Vec::<String>::new(), "{script}");
        assert_eq!(mounts(tmp.path()), Vec::<String>::new(), "{script}");
    }

    // While `run` still copies the image, half a container is on disk.
    std::fs::write(
        step.join("Containerfile"),
        "FROM localhost/i:1\nRUN /bin/dd if=/dev/zero of=/big bs=1m count=100\n",
    )
    .unwrap();
    ok(&["build", "-t", "big:1", step.to_str().unwrap()]);
    let containers = || {
        std::fs::read_dir(state.join("containers"))
            .unwrap()
            .filter(|e| {
                let entry = e.as_ref().unwrap();
                !entry.file_name().to_string_lossy().starts_with('.')
            })
            .count()
    };
    let mut run = jailer()
        .args(["run", "--rm", "--entrypoint", "/bin/sleep", "big:1", "7725"])
        .process_group(0)
        .spawn()
        .unwrap();
    wait_for("the container never appeared", &mut || containers() > 0);
    unsafe { libc::kill(-(run.id() as i32), libc::SIGINT) };
    let status = run.wait().unwrap();
    assert_eq!(status.code(), Some(130), "{status:?}");
    assert_eq!(containers(), 0);
    assert_eq!(jails(tmp.path()), Vec::<String>::new());
    assert_eq!(mounts(tmp.path()), Vec::<String>::new());
}

#[test]
#[ignore = "needs root: scripts/jailer.qualify runs it"]
fn another_users_state_directory_is_refused_by_name() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    if !live("another_users_state_directory_is_refused_by_name") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let state = tmp.path().join("state");
    let jailer = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_jailer"));
        c.args(["--state-dir", state.to_str().unwrap(), "--no-zfs"])
            .args(args);
        c
    };
    assert!(jailer(&["images"]).status().unwrap().success());
    for command in [&["images"][..], &["ps", "-a"][..], &["logs", "any"][..]] {
        let out = jailer(command).uid(65534).gid(65534).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{command:?}");
        assert!(
            err.contains("another user's state directory"),
            "{command:?}: {err}"
        );
    }
}

#[test]
#[ignore = "needs root: scripts/jailer.qualify runs it"]
fn a_failing_stage_nothing_needs_does_not_run() {
    if !live("a_failing_stage_nothing_needs_does_not_run") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let ctx = tmp.path().join("ctx");
    std::fs::create_dir_all(&ctx).unwrap();
    std::fs::write(
        ctx.join("Containerfile"),
        "FROM docker.io/freebsd/freebsd-runtime:15.1 AS unused\nRUN false\n\
         FROM docker.io/freebsd/freebsd-runtime:15.1 AS wanted\nRUN : > /built\n",
    )
    .unwrap();
    let build = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_jailer"))
            .args(["--state-dir"])
            .arg(tmp.path().join("state"))
            .args(["--no-zfs", "build"])
            .args(args)
            .arg(&ctx)
            .output()
            .unwrap()
    };
    let out = build(&[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = build(&["--target", "unused"]);
    assert!(
        !out.status.success(),
        "the stage still fails when asked for"
    );
}
