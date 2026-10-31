# TODO

What jailer still lacks next to buildah, ordered by how much it matters to
people building images for Legion.

## 1. Must have

- [x] **Multi-architecture images.** `jailer manifest push <target>
  <source>...` publishes an OCI index naming one image per platform, from
  local images and images already pushed from other architectures' build
  hosts. Tested against a mock registry; still to try against a real one
  (GHCR, Docker Hub) and on an arm64 host.

- [ ] **Packaging.** buildah is `pkg install buildah`; jailer has to be
  built from source. Add a port (`sysutils/jailer`) and release binaries
  for amd64 and aarch64.
  *Done when* `pkg install jailer` works, and Legion's `docs/IMAGES.md`
  links to it.

## 2. Build speed

- [x] **Stop rehashing the whole root filesystem on every step.** Each
  step now starts from the previous step's state and hashes only files
  whose size, mtime, ctime or inode changed. A build with 6 s of work
  went from 24 s to 6.8 s (release build); a fully cached one takes 0.6 s.

- [x] **Keep the build cache across `rmi`.** Layers the cache names are
  kept, builder stages included, until `jailer prune --cache`.
- [ ] **A size limit for the build cache**, evicting least recently used
  entries, so it need not be cleared by hand.

- [x] **`RUN --mount=type=cache`.** A host directory kept between builds,
  never in a layer.

## 3. Containerfile compatibility

Containerfiles written for Docker or Podman should build unchanged, or
fail with a clear message.

- [x] **`RUN --mount=type=secret` and `build --secret id=...,src=...`**
  (or `env=VAR`).
- [x] **`RUN --mount=type=bind`** (context or `from=<stage>`, `rw` writes
  discarded), **`type=tmpfs`**, and `RUN --network=none|host`.
- [ ] **`RUN --mount=type=bind,from=<image>`** and **`type=ssh`**.
- [ ] **`.containerignore` for context bind mounts.** A `RUN` bind mount of
  the context shows ignored files too (Docker hides them).
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
