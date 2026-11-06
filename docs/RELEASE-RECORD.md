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

`--record` also works with `manifest push` and `sign`. A `build` starts a new
record. The other commands add to the file, and start one if it is not there,
without a build's `source` and `bases`. `--backend buildah` has no record.

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
| `published` | Each push: `reference` as pushed, `digest`, `pinned`, and `signature`, where the signature is, if it was signed. |
| `published[].platforms` | For an index: each platform's manifest digest. `digest` is then the index's. |
| `verified` | Each good signature check: `digest`, `reference`, and `key`, the digest of the public key's file. |
| `archives` | Each export: `file`, its `sha256`, and the `manifest` inside. |

These are three different digests: an image's config, its manifest, and an index
holding that manifest. A multi-architecture release records the index and which
manifest each platform gets.

A record holds digests and names only. Secrets, build arguments and credentials
stay out of it. A base's `reference` is written as the Containerfile gives it.

## What a record does not do

`verified` says a signature was good when jailer checked it. It does not stop a
deployment: enforcing that is the job of the deployment's own policy, and Legion
does not read these records yet. See `ROADMAP.MD`.

An offline archive keeps the image's manifest digest, which `archives[].manifest`
records. A signature lives in the registry, so it does not travel in the archive.

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
