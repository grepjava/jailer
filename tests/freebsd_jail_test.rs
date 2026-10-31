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
