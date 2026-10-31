#![cfg(target_os = "freebsd")]

use std::path::Path;
use std::process::Command;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn real_freebsd_jail_build_run_export_workflow() {
    if !is_root() {
        eprintln!("skipping real_freebsd_jail_build_run_export_workflow (requires root)");
        return;
    }

    let bin = env!("CARGO_BIN_EXE_jailer");
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().join("state");
    let project_dir = tmp.path().join("hello-service");
    std::fs::create_dir_all(&project_dir).unwrap();

    let zfs_root = format!("zroot/jailer-test-{}", std::process::id());

    // Ensure cleanup of test ZFS dataset on exit
    struct ZfsGuard(String, std::path::PathBuf);
    impl Drop for ZfsGuard {
        fn drop(&mut self) {
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
            "18080:8080",
            "--entrypoint",
            "/bin/sh",
            "nc:1",
            "-c",
            "echo hello | /usr/bin/nc -N -l 8080",
        ]);
        let ps = cmd(&["ps"]);
        assert!(
            ps.contains("10.88.0.") && ps.contains("18080:8080/tcp"),
            "{ps}"
        );
        let ip = ps
            .split_whitespace()
            .find(|w| w.starts_with("10.88.0."))
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
fn run_mounts_reach_the_step_but_not_the_image() {
    if !is_root() {
        eprintln!("skipping run_mounts_reach_the_step_but_not_the_image (requires root)");
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
CMD ["/bin/sh", "-c", "for f in count bound secretlen tmpfs ifs ctxls fromimg hd sb ssh two; do printf '%s=%s ' $f $(cat /$f); done; for d in /var/cache/thing /data /run/secrets /scratch /ctx /img /run/buildkit; do test -e $d && printf 'leaked=%s ' $d; done; echo"]
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
        "count=1 bound=original secretlen=12 tmpfs=yes ifs=lo0 ctxls=a.txt fromimg=yes hd=heredoc-2 sb=shebang ssh=/run/buildkit/ssh_agent.0 two=x-5 y-$((2+3))="
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
}
