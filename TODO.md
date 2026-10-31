# TODO

What jailer still lacks next to buildah, ordered by how much it matters to
people building images for Legion.

## 1. Must have

- [x] **Multi-architecture images.** `jailer manifest push <target>
  <source>...` publishes an OCI index naming one image per platform, from
  local images and images already pushed from other architectures' build
  hosts. Tested against a mock registry and Docker's `registry:2`, and
  the test suite passes on arm64 (FreeBSD 15.1 VM); still to try against
  GHCR, with the aarch64 tarball's upload.

- [ ] **Packaging.** v0.4.0 is released with an amd64 tarball, built by
  `scripts/release.sh`, and the port in `ports/sysutils/jailer` builds
  and packages 0.4.0 (portlint clean), with Legion's git crates fetched by
  the ports framework (`scripts/port-crates.sh` lists them) and libzstd
  from `archivers/zstd`. An aarch64 tarball is built (on a FreeBSD 15.1
  arm64 VM, all tests passing) but not yet uploaded; both tarballs need
  15.1 or later (libc's FBSD_1.9). Still to do: submitting the port to
  FreeBSD so that `pkg install jailer` works; then link it from Legion's
  `docs/IMAGES.md`. At
  each release: set `DISTVERSION`, run `scripts/port-crates.sh`, then
  `make makesum package` and `portlint -AC` on a FreeBSD host.

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
- [x] **`COPY --from=<image>`**, not only a stage.
- [x] **File flags and hard links in built layers**: `schg` and the like
  as bsdtar's `SCHILY.fflags`, and each hard-linked file with all its
  names.
- [x] **`build --param` and `--sysv`**: jail parameters and SysV IPC for
  `RUN` steps.

## 4. Nice to have

- [x] **Clearer pull errors**: "not found, or access denied".
- [x] **Podman interop.** `export` also writes Docker's `manifest.json`, as
  `docker save` does. `docker load` (Docker 29) loads it, and `docker
  pull` takes pushed images, zstd ones too; `podman load` (Podman 5.8 on
  FreeBSD 15) loads gzip and zstd archives and runs them.
- [x] **Image signing**: `push --sign-key`, `sign`, `verify` and `key
  generate`, signatures as cosign makes them with a key pair (no
  transparency log, no keyless signing). cosign 2.4 and 3.0 verify
  jailer's signatures, and `jailer verify` cosign's.
- [x] **`build --squash`** flattens the image into one layer.
- [x] **Man page note** on `schg` files in a `--no-zfs` state directory.
- [x] **One runtime with Legion.** Images, the store and the registry
  client are Legion's `legion-image`, and containers and `RUN` steps
  Legion's `legion-jail` (v0.1.1): `jailer run` gets Legion's security
  defaults, and `--vnet` runs a pod as a node does.
- [ ] **Same config, different layers.** Legion's store keeps one image
  per config digest, so a gzip and a zstd build of one Containerfile
  (same diff_ids, so same config) become one image: the later build's
  layers replace the earlier's under both tags, and the record's manifest
  digest stays the first build's. Fixed in Legion's main (an image is its
  config and manifest digests together); move to the next Legion tag.

## 5. Later

- [x] **ZFS clones for build stages**: with a ZFS store, a stage is a
  clone of its base image's top layer, or of a snapshot of the stage it is
  built on, kept under `<zfs-root>/build` and destroyed with the build.
- [x] **Network for `run --vnet`**: an epair on jailer's own bridge
  (`jailer0`, 10.88.0.0/16), NAT out and `-p` published ports through pf
  anchors under `jailer/`; `--network none` for loopback only.
- [x] **Legion's `PodNetwork`** makes `jailer0` and the pods' epairs
  (Legion v0.1.4), IPv4 only and with a 1500-byte MTU.
- [x] **Resource limits**: `-m`, `--cpus`, `--pids-limit` for `run` and
  `build`, as rctl rules (memory per process, as on a Legion node).
- [x] **`--cpuset-cpus`** for `run` and `build`, set by legion-jail on
  the jail before anything runs in it (Legion v0.1.3).
- [x] **`build --label` and `--timestamp`** (or `SOURCE_DATE_EPOCH`).
- [x] **`build --annotation`**: manifest annotations (Legion v0.1.3).
- [x] **zstd layers**: `build --compression zstd`.
- [x] **A registry-backed build cache**: `--cache-to REF` pushes a
  build's `RUN` steps as an OCI manifest; `--cache-from REF` takes them on
  another host, downloading only the layers of the steps it uses.

## Not planned

- **Building without root.** `RUN` steps and `jailer run` create jails,
  which needs root. buildah's rootless mode depends on Linux user
  namespaces, which FreeBSD does not have.
- **Building images without a Containerfile** (buildah's `from`, `run`,
  `copy`, `commit` commands). Containerfiles cover the Legion workflow.
