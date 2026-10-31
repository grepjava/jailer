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
