# TODO

What jailer still lacks next to buildah, ordered by how much it matters to
people building images for Legion.

## 1. Must have

- [ ] **Multi-architecture images.** Legion runs on amd64 and aarch64 nodes
  and picks its architecture from an image index. jailer pushes one
  architecture per name, so its images run only on matching nodes.
  Jails share the host kernel, so cross-building is out: build on each
  architecture, then combine.
  *Done when* `jailer manifest create <name> <img-amd64> <img-arm64>` and
  `jailer manifest push <name> <registry/repo:tag>` publish an OCI index
  that Legion nodes of both architectures pull.

- [ ] **Packaging.** buildah is `pkg install buildah`; jailer has to be
  built from source. Add a port (`sysutils/jailer`) and release binaries
  for amd64 and aarch64.
  *Done when* `pkg install jailer` works, and Legion's `docs/IMAGES.md`
  links to it.

## 2. Build speed

- [ ] **Stop rehashing the whole root filesystem on every step.** Each
  `COPY` and `RUN` hashes every file before and after it runs: a build
  with 6 s of work takes about 24 s. Skip files whose size, mtime and
  inode did not change, or use `zfs diff` between snapshots in ZFS mode.
  *Done when* a step's overhead is under a second on
  `freebsd-runtime:15.1`.

- [ ] **Keep the build cache across `rmi`.** Cached layers live only while
  some image uses them, so a multi-stage build's builder stage (the
  expensive `cargo build` or `go build`) is lost at the next `rmi` of
  anything. Keep the layers that cache entries name, and add
  `jailer prune [--cache]` with a size limit to reclaim them.
  *Done when* a Rust project rebuilds its builder stage from cache after
  an unrelated `rmi`.

- [ ] **`RUN --mount=type=cache`.** Lets `pkg`, cargo and npm keep their
  downloads between builds without putting them in the image. Today
  `RUN --mount=...` is passed to `/bin/sh` and fails with exit 127.
  *Done when* `RUN --mount=type=cache,target=/var/cache/pkg pkg install ...`
  reuses downloads across builds and leaves nothing in the layer.

## 3. Containerfile compatibility

Containerfiles written for Docker or Podman should build unchanged, or
fail with a clear message.

- [ ] **`RUN --mount=type=secret` and `build --secret id=...,src=...`** for
  build-time credentials (private package repos, git tokens) that stay out
  of the image.
- [ ] **`RUN --mount=type=bind`**, and `RUN --network=none|host`.
- [ ] **Heredocs** in `RUN` and `COPY` (`RUN <<EOF ... EOF`).
- [ ] **`ADD <url>`**, with `--checksum=sha256:...`. Today it fails with
  "source not found".
- [ ] **`ONBUILD`**: store the triggers in the image config and run them
  when the image is used as a base. Today they are recorded in history
  only.
- [ ] **`FROM --platform`**: honour it, or reject a platform the host
  cannot run. Today it is parsed and ignored.
- [ ] **`COPY --exclude`, `--parents`, `--link`.**
- [ ] **Wildcards anywhere in a source path** (`src/*/Cargo.toml`), not only
  in the last component.
- [ ] **Parser directives**: support `# escape=`; accept `# syntax=` with a
  warning that it is ignored.

## 4. Nice to have

- [ ] **Clearer pull errors.** Docker Hub answers 401 for a repository that
  does not exist; say "not found or access denied" instead of "access
  denied (no credentials)".
- [ ] **Podman interop.** `export --format docker-archive`, so an image can
  go to `podman load` or `docker load` as well as `legion image load`.
- [ ] **Image signing** with sigstore/cosign signatures on `push`.
- [ ] **`build --squash`** to flatten the result into one layer.
- [ ] **Man page note** that a `--no-zfs` state directory holds files with
  the `schg` flag, so removing it by hand needs `chflags -R noschg` first.

## Not planned

- **Building without root.** `RUN` steps and `jailer run` create jails,
  which needs root. buildah's rootless mode depends on Linux user
  namespaces, which FreeBSD does not have.
- **Building images without a Containerfile** (buildah's `from`, `run`,
  `copy`, `commit` commands). Containerfiles cover the Legion workflow.
