# Containerfile compatibility

What jailer's native builder does with a Containerfile written for Docker or
Podman. A Containerfile should build unchanged, or fail with a message saying
why. Where jailer behaves differently, this page says so.

What is claimed here was tested with:

| Tool | Version | Platform | Recorded in |
|---|---|---|---|
| BuildKit | Docker 29.7.2, buildx 0.36.1 | Linux | `tests/compat/expected/buildkit` |
| Buildah | Podman 5.8.6 (Buildah 1.43.2) | FreeBSD 15.1 | `tests/compat/expected/buildah` |
| jailer | this tree | FreeBSD 15.1, and Windows without file modes | `tests/compat_test.rs` |

`tests/compat_test.rs` builds every case in `tests/compat/cases` and compares
the image's config and files with both tools' records. A difference fails the
test unless `tests/compat/differences.buildkit` or `.buildah` names it, with
the reason. The cases use `FROM scratch`, so they cover parsing, variables,
copies, stages and image config, not `RUN`, which the jail tests cover. Run
`scripts/compat-reference.py` and `scripts/compat-buildah.sh` to record again.

Intended differences between FreeBSD and Linux are not counted: jailer sets no
default `PATH` on an image from scratch, where BuildKit sets Linux's, and leaves
the default working directory unset rather than `/`.

## Instructions

| Instruction | Status | Notes |
|---|---|---|
| `FROM` | Supported | `--platform` is the only flag, and only this host's platform: there is no emulation. Other flags are refused. |
| `ARG`, `ENV`, `LABEL` | Supported | `$VAR`, `${VAR}`, `${VAR:-x}`, `${VAR-x}`, `${VAR:+x}` and `${VAR+x}`. `${VAR#x}`, `${VAR%x}`, `${VAR/x/y}` and `${VAR:?x}` are refused, though BuildKit has them. See [ARG and ENV](#arg-and-env). |
| `RUN` | Supported | Runs in a jail, and needs root. Flags below. |
| `COPY`, `ADD` | Supported | Flags below. A tar goes through `ADD` unpacked. |
| `CMD`, `ENTRYPOINT` | Supported | Shell and exec forms. A JSON array of anything but strings is refused. |
| `WORKDIR`, `USER` | Supported | A `WORKDIR` after `USER` belongs to that user, who must be in the image. |
| `EXPOSE`, `VOLUME`, `STOPSIGNAL`, `SHELL` | Supported | Kept in the image config. |
| `ONBUILD` | Supported | Runs for an image or stage built on this one. `ONBUILD ONBUILD`, `FROM` and `MAINTAINER` are refused. |
| `MAINTAINER` | Supported | Sets the image's author, as in Docker, where it is deprecated. |
| `HEALTHCHECK` | Accepted, not kept | Not written to the image. Legion ignores it, so `jailer check` warns (LEGION001): configure probes instead. |
| Anything else | Refused | |

## Flags

| Flag | Status |
|---|---|
| `COPY --from` | A stage by name or index, or an image. |
| `COPY --chown`, `--chmod` | Supported. `--chmod` takes octal only. |
| `COPY --exclude`, `--parents` | Supported, with `/./` for `--parents`. BuildKit needs a labs `# syntax=` for them. |
| `COPY --link` | Accepted, changes nothing: jailer always rebuilds layers from content. |
| `ADD --checksum` | Supported for a URL. |
| `ADD <git URL>`, `ADD --keep-git-dir` | Refused, for an http(s) URL ending in `.git` and a `git@` or `git://` source alike. |
| `RUN --mount=type=cache` | Supported. `from` is refused. |
| `RUN --mount=type=bind` | The context, a stage or an image. Writes with `rw` are discarded. |
| `RUN --mount=type=secret`, `ssh`, `tmpfs` | Supported. |
| `RUN --network` | `none`, `default` and `host`. |
| `RUN --security` and others | Refused. |

Unknown flags and mount options are refused, not ignored.

## Parser directives and contexts

| Item | Status |
|---|---|
| `# escape=` | Supported. |
| `# syntax=` | Ignored, with a warning: jailer parses the Containerfile itself. Features are not chosen by it. |
| Here-documents | Supported in `RUN`, `COPY` and `ADD`, including `#!` scripts. |
| `.containerignore`, `.dockerignore` | Both, and `.containerignore` wins. `!` lines work as in Docker. |
| Build contexts | A local directory only. `--build-context`, URLs and Git contexts are not supported. |

## Stages and platforms

Only the target, and the stages it needs, are built. That is `--target`, or the
last stage. A stage is needed through `FROM`, `COPY --from`, a bind mount's
`from`, or an `ONBUILD` trigger, including one from a base image. A source given
by a variable keeps every stage before it, as its value is known only when the
step runs. Stages run one at a time.

`BUILDPLATFORM`, `TARGETPLATFORM`, `BUILDOS`, `TARGETOS`, `BUILDARCH` and
`TARGETARCH` are set, all to this host. A foreign `FROM --platform` is refused.

## Build cache

`--cache-to` and `--cache-from` use jailer's own format, an OCI manifest with
config type `application/vnd.jailer.build-cache.config.v1+json`. It travels
through any OCI registry, but it is not a BuildKit cache: neither tool reads the
other's.

## Where the tools differ

BuildKit and Buildah do not always agree. jailer follows BuildKit, except where
that would lose files.

| Case | BuildKit | Buildah | jailer |
|---|---|---|---|
| `ARG` with a value after an `ENV` of its name | `ARG` wins in later steps; the image keeps `ENV` | `ENV` wins | As BuildKit |
| `COPY go.sum* ./` matching nothing | Copies nothing | Refused | As BuildKit |
| `COPY a b /file`, no `/` | Keeps only `b`, as `/file` | Directory `/file/` | As Buildah: nothing is lost |
| `COPY *.txt /file` matching several, no `/` | Keeps only the last | Keeps only the last | Directory `/file/`: nothing is lost |
| `COPY ../a /x` | Reads `a` in the context | Reads `a` in the context | Refused: the path leaves the context |
| `WORKDIR` after a `USER` not in the image | Refused | Builds | As BuildKit |
| `CMD echo` after `SHELL` | Uses that shell | Uses `/bin/sh` | As BuildKit |
| `\` with `# escape=` a backtick | Ordinary | Removed | As BuildKit |
| `${VAR-default}` | Supported | Refused | As BuildKit |
| `${VAR#x}`, `${VAR%x}`, `${VAR/x/y}` | Supported | Supported | Refused, rather than left empty |

### ARG and ENV

An `ENV` after an `ARG` of the same name wins. An `ARG` with a value, from a
default, `--build-arg` or a global `ARG`, wins for the steps after it, even over
an earlier `ENV`, though the image keeps the `ENV`. An `ARG` with no value
changes nothing.
