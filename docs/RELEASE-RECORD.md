# Release records

A release record is a JSON file that follows one image from its build to where
it was published. It says exactly what to deploy, and lets a later step prove it
is handling that same image.

```sh
jailer build -t app:1 --record release.json .
jailer push --record release.json --sign-key cosign.key app:1 ghcr.io/me/app:1
jailer verify --record release.json --key cosign.pub ghcr.io/me/app:1
jailer export --record release.json app:1 app.tar
```

Deploy the `pinned` reference from `published`, which names a digest. A tag can
move later, and `pinned` cannot.

`--record` also works with `manifest push`, `sign` and `attest`. A `build` starts a new
record. The other commands add to the file, and start one if it is not there,
without a build's `source` and `bases`. `--backend buildah` has no record.

## Several platforms

`jailer publish` builds natively on a host for each platform and pushes one
index of them:

```sh
jailer publish --host freebsd/amd64=me@amd64-host --host freebsd/arm64=me@arm64-host \
    --record release.json --sign-key cosign.key ghcr.io/me/app:1 .
```

Each host needs `jailer`, `tar`, and its own login to the registry: no
credentials are sent to it. `publish` sends the same context to every host, as a
build sees it, and they build at once. Each host pushes to a staging tag of its
own, `app:1-freebsd-arm64` here, and removes its working directory however it
ends.

The index goes to `app:1` only when every host has finished, each built the
platform it was named for, and all had the same Containerfile and context. If
not, the command fails naming the hosts, and `app:1` stays as it was. Staging tags
already pushed stay in the registry, and the next `publish` replaces them.
Stopping `publish` drops the ssh connections: a host may finish its step, but
nothing is published.

The record has `builds`, each platform's image and bases, in place of `image`,
and `published` has the index with its `platforms`. `jailer manifest push` and
per-host builds still work as before. It has been tested through a stand-in for ssh on one
host, not yet across two real architectures: see `ROADMAP.MD`.

## A record cannot mix images

- `push` and `export` refuse an image other than the record's. `push` checks
  before it sends anything, so a refused push leaves the registry as it was.
- `verify` and `sign` refuse a digest the record does not name. If a tag has
  moved to another image, even one signed by the same key, `verify --record`
  fails and the record is left as it was.
- `manifest push` refuses an index without the record's image. It can only tell
  once the index is pushed: the index stays in the registry, and is not recorded.

## Fields

| Field | Meaning |
|---|---|
| `schema` | The format's version, now 1. jailer refuses a newer one. |
| `builder` | The jailer that last wrote the record. |
| `image.config` | The digest of the image's config, which is also its image ID. |
| `image.manifest` | The digest of its manifest, which a registry and Legion go by. |
| `image.platform` | `os/architecture`. |
| `source.containerfile` | The digest of the Containerfile. |
| `source.context` | One digest over the files a build can see: paths, kinds, modes and contents. Ignored files, times and owners do not count. |
| `bases` | Each image built from or copied from: `reference` as named, with its `config` and `manifest` as resolved. |
| `builds` | From `publish`: for each platform, its `image`, `bases`, and `builder`. |
| `published` | Each push: `reference` as pushed, `digest`, `pinned`, and `signature`, where the signature is, if it was signed. |
| `published[].platforms` | For an index: each platform's manifest digest. `digest` is then the index's. |
| `verified` | Each good signature check: `digest`, `reference`, and `key`, the digest of the public key's file. |
| `attestations` | Each attestation pushed: `digest`, `predicateType`, and `reference`, where it is. |
| `archives` | Each export: `file`, its `sha256`, and the `manifest` inside. |

These are three different digests: an image's config, its manifest, and an index
holding that manifest. A multi-architecture release records the index and which
manifest each platform gets.

A record holds digests and names only. Secrets, build arguments and credentials
stay out of it. A base's `reference` is written as the Containerfile gives it.

## Attestations

```sh
jailer attest --key cosign.key --type provenance --record release.json ghcr.io/me/app@sha256:...
jailer attest --key cosign.key --type sbom --image app:1 --record release.json ghcr.io/me/app@sha256:...
jailer verify --key cosign.pub --type provenance ghcr.io/me/app@sha256:...
```

An attestation is an in-toto statement in a DSSE envelope, signed with the same
keys as a signature and kept as cosign keeps them, at the tag `sha256-<hex>.att`.
`jailer verify --type` prints the predicate if it is good. Tested with cosign
3.1.4, which reads both kinds with `verify-attestation --type slsaprovenance1` or
`--type spdxjson` and `--insecure-ignore-tlog`, as no transparency log entry is
made. There is no keyless signing. `scripts/attest-check.sh` repeats that test.

- `--type provenance` is SLSA provenance v1, from the record: the digests of the
  Containerfile and the context, and each base as resolved. Build arguments are
  left out, as they may hold what is not to be published, so provenance does not
  tell two builds apart that differ only there.
- `--type sbom` is an SPDX 2.3 document, also printed by `jailer sbom`. It needs
  the local image with the same manifest digest, and `pkg(8)` on the host.

An SBOM lists only packages registered with `pkg(8)`. Files put in the image any
other way, such as by `COPY` or a build from source, are not in it, and the
document says so. An image with no package database gets a document saying it is
not an inventory, not an empty list that reads as complete.

## What a record does not do

`verified` says a signature was good when jailer checked it. It does not stop a
deployment: enforcing that is the job of the deployment's own policy, and Legion
does not read these records yet. See `ROADMAP.MD`.

An offline archive keeps the image's manifest digest, which `archives[].manifest`
records. Signatures and attestations live in the registry, so they do not travel
in the archive.

## `jailer check --json`

`jailer check --json` prints one object on standard output:

```json
{
  "schema": 1,
  "target": ".",
  "passed": false,
  "findings": [
    { "severity": "error", "code": "LEGION003", "message": "..." }
  ]
}
```

`severity` is `warning` or `error`. A `code` keeps its meaning; a `message` may be
reworded. The exit status is 0 unless a finding is an error. A check that cannot
run at all, as with no Containerfile or image, exits non-zero with its reason on
standard error and nothing on standard output.
