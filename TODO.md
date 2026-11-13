# TODO

What jailer still lacks next to buildah, ordered by how much it matters to
people building images for Legion.

## 1. Must have

- [x] **Multi-architecture images.** `jailer manifest push <target>
  <source>...` publishes an OCI index naming one image per platform, from
  local images and images already pushed from other architectures' build
  hosts. Tested against a mock registry and Docker's `registry:2`, and on
  GHCR: an amd64 image pushed from one host and an arm64 one from another,
  one signed index naming both, each architecture pulling its own. The
  full test suite passes on arm64 (FreeBSD 15.1 VM, 2026-11-12), and
  Legion's handoff tests run a signed two-architecture index jailer made.

- [ ] **Packaging.** v0.5.5 is released with an amd64 tarball (aarch64 to come),
  built by `scripts/release.sh` on FreeBSD 15.1 (they need its libc,
  FBSD_1.9). The port in `ports/sysutils/jailer` is at 0.5.5 (FreeBSD 15+,
  amd64 and aarch64), with Legion's git crates fetched by the ports
  framework (`scripts/port-crates.sh` lists them) and libzstd from
  `archivers/zstd`; `poudriere testport` passes on 15.1 amd64, and its
  `git format-patch` against freebsd-ports main is filed on Bugzilla as
  PR 300442 (2026-11-02). Still to do: see it through review, then link
  jailer from Legion's `docs/IMAGES.md`. At each release: set `DISTVERSION`, run
  `scripts/port-crates.sh`, then `make makesum package` and `portlint
  -AC` on a FreeBSD host, and build the tarballs on both architectures'
  hosts at once (`release.sh` writes one `SHA256SUMS` for all of them).

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
  agent through a socket of the step's own, bound at the target in the
  stage's root for the step (nullfs cannot mount sockets).
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
- [x] **A `\` before a `$` no longer stops a variable expanding.** With
  `ARG VAR=x`, `ENV P=a\\$VAR` gives `a\x`, and with a backtick as the
  escape `ENV P=C:\$VAR` gives `C:\x`, as in Docker (both gave a literal
  `$VAR` before). The parser takes quotes and escapes away and the build
  expands variables later, so a `$` that must not expand (escaped, or in
  single quotes) is handed on with a mark. That mark was a `\`, which a
  word can also hold for real; it is now a character no Containerfile
  holds, and the parser's words expand with `expand_word`, where a `\`
  is plain text. Text as written (a `COPY` here-document's body) takes a
  `\` as BuildKit does: it escapes the character after it, whatever it is. `WORKDIR`, `USER`, `STOPSIGNAL` and the
  one-value `ENV` now have quotes and escapes taken away throughout, not
  only around the whole value.

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
- [x] **Same config, different layers.** Legion's store keeps one image
  per config digest, so a gzip and a zstd build of one Containerfile
  (same diff_ids, so same config) become one image: the later build's
  layers replace the earlier's under both tags, and the record's manifest
  digest stays the first build's. Fixed in Legion v0.1.7 (an image is its
  config and manifest digests together).

## 5. Later

- [x] **ZFS clones for build stages**: with a ZFS store, a stage is a
  clone of its base image's top layer, or of a snapshot of the stage it is
  built on, kept under `<zfs-root>/build` and destroyed with the build.
- [x] **Network for `run --vnet`**: an epair on jailer's own bridge
  (`jailer0`, 10.77.0.0/16), NAT out and `-p` published ports through pf
  anchors under `jailer/`; `--network none` for loopback only.
- [x] **Legion's `PodNetwork`** makes `jailer0` and the pods' epairs
  (Legion v0.1.4), IPv4 only and with a 1500-byte MTU.
- [x] **Resource limits**: `-m`, `--cpus`, `--pids-limit` for `run` and
  `build`, as rctl rules (memory per process; see `docs/LOCAL-AND-LEGION.md`).
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
