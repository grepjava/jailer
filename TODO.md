# TODO

What jailer still lacks next to buildah, ordered by how much it matters to
people building images for Legion.

## 1. Must have

- [x] **Multi-architecture images.** `jailer manifest push <target>
  <source>...` publishes an OCI index naming one image per platform, from
  local images and images already pushed from other architectures' build
  hosts. Tested against a mock registry; still to try against a real one
  (GHCR, Docker Hub) and on an arm64 host.

- [ ] **Packaging.** v0.1.0 is released with an amd64 tarball, built by
  `scripts/release.sh`, and the port overlay in `ports/sysutils/jailer`
  builds, packages and installs (`make package`, portlint clean). Still to
  do: an aarch64 tarball (run the script on an arm64 host), and submitting
  the port to FreeBSD so that `pkg install jailer` works; then link it from
  Legion's `docs/IMAGES.md`.

## 2. Build speed

- [x] **Stop rehashing the whole root filesystem on every step.** Each
  step now starts from the previous step's state and hashes only files
  whose size, mtime, ctime or inode changed. A build with 6 s of work
  went from 24 s to 6.8 s (release build); a fully cached one takes 0.6 s.

- [x] **Keep the build cache across `rmi`.** Layers the cache names are
  kept, builder stages included, until `jailer prune --cache`.
- [x] **A size limit for the build cache**: `build --cache-max` (default
  10g, by compressed size) drops the least recently used cached layers.

- [x] **`RUN --mount=type=cache`.** A host directory kept between builds,
  never in a layer.

## 3. Containerfile compatibility

Containerfiles written for Docker or Podman should build unchanged, or
fail with a clear message.

- [x] **`RUN --mount=type=secret` and `build --secret id=...,src=...`**
  (or `env=VAR`).
- [x] **`RUN --mount=type=bind`** (context or `from=<stage>`, `rw` writes
  discarded), **`type=tmpfs`**, and `RUN --network=none|host`.
- [x] **`RUN --mount=type=bind,from=<image>`**, and `.containerignore`
  applied to context bind mounts.
- [x] **`RUN --mount=type=ssh`** and `build --ssh`: jailer relays the
  agent through a socket of the step's own (nullfs cannot mount sockets).
- [x] **Heredocs** in `RUN`, `COPY` and `ADD`, including `#!` scripts.
- [x] **`ADD <url>`**, with `--checksum=sha256:...`. Git URLs are not
  supported.
- [x] **`ONBUILD`**: triggers are kept in the image config and run when it
  is used as a base.
- [x] **`FROM --platform`** and the `BUILDPLATFORM`/`TARGET*` args: the
  host's platform is accepted, any other refused (no emulation).
- [x] **`COPY --exclude`, `--parents`** (with `/./`); `--link` is accepted
  and changes nothing.
- [x] **Wildcards anywhere in a source path**, and `[...]` classes.
- [x] **Parser directives**: `# escape=`; `# syntax=` is ignored with a
  warning.

## 4. Nice to have

- [x] **Clearer pull errors**: "not found, or access denied".
- [x] **Podman interop.** `export` also writes Docker's `manifest.json`, as
  `docker save` does. Still to try with `podman load` and `docker load`.
- [ ] **Image signing** with sigstore/cosign signatures on `push`.
- [x] **`build --squash`** flattens the image into one layer.
- [x] **Man page note** on `schg` files in a `--no-zfs` state directory.

## Not planned

- **Building without root.** `RUN` steps and `jailer run` create jails,
  which needs root. buildah's rootless mode depends on Linux user
  namespaces, which FreeBSD does not have.
- **Building images without a Containerfile** (buildah's `from`, `run`,
  `copy`, `commit` commands). Containerfiles cover the Legion workflow.
