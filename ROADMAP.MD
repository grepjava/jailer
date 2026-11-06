# Jailer roadmap

Reviewed at `1562c2c` (four commits after v0.5.3) on 2026-11-06. Sequencing
revised the same day against v0.5.4 and Legion v0.1.12's roadmap.

Jailer is a standalone FreeBSD OCI image builder, local jail test runner,
compatibility checker and registry publisher. This roadmap compares its
workflow with Buildah and Docker BuildKit, and its local testing with Podman.
It prioritizes predictable builds and verified FreeBSD behavior while keeping
image building outside Legion's cluster daemon.

This is a source-based assessment, not a live qualification report. Tests were
not run during the review. Implementation status does not establish production
reliability. `TODO.md` retains existing implementation and packaging tracking;
this document describes the broader development priorities.

## Existing capabilities

Do not treat these as features still needing implementation:

- Native Containerfile parsing, jail-based `RUN`, multi-stage builds, stage
  inheritance, `COPY --from` stages or images, and `--target`.
- Cache, bind, secret, SSH and tmpfs build mounts, including cache-sharing locks.
- Heredocs, `ONBUILD`, URL checksums, copy exclusions and parent paths.
- Local build caching, size trimming, registry-backed cache, and ZFS stage clones.
- Deterministic layer metadata and image timestamp controls. Reproducibility
  still depends on the inputs and commands used by a build.
- OCI pull, push, import and export, gzip/zstd layers, and multi-architecture
  index publishing from separately built platform images.
- Cosign-compatible P-256 key-based image signing and verification.
- Interactive and detached local runs, exec, logs, nullfs mounts, VNET,
  published ports, resource controls and opt-in Linux ABI support.
- Shared Legion image and jail-runtime components, plus compatibility checks.

## Current parity boundaries

| Area | Current boundary |
|---|---|
| Stage execution | Native builds execute only the stages the target needs, one at a time in file order. |
| Containerfile syntax | Broad support, tested against BuildKit and Buildah: see `docs/COMPATIBILITY.md`. |
| Build platforms | Native builds target the host platform and reject foreign `FROM --platform` values. Publishing a multi-architecture index does not coordinate the builds. |
| Registry cache | OCI transport with a Jailer-specific cache configuration format; not an interchangeable BuildKit cache. |
| Memory limits | RCTL limits resident memory per process. Legion's agent also holds a container's total, which `jailer run` does not: decided, see `docs/LOCAL-AND-LEGION.md`. |
| Image trust | Key-based signatures exist; SBOM/provenance attestations, keyless signing and transparency-log integration are absent from the reviewed interface. |
| Runtime equivalence | Local jail execution shares runtime primitives, but does not reproduce the full Legion agent, probes, reconciliation or service lifecycle. |
| Qualification | FreeBSD live tests are compiled only on FreeBSD and run through `scripts/qualify`, on amd64 so far. The checkout has no `.github` workflow directory. |

## P0 — Repeatable FreeBSD qualification

Make privileged integration coverage explicit and repeatable before expanding
the runtime or build scheduler.

Deliverables:

- A dedicated qualification entry point or CI lane on disposable FreeBSD hosts.
- Coverage on amd64 and arm64, with ZFS and plain-directory storage.
- Clear reporting of executed and skipped privileged tests. A required live
  qualification run must fail if its prerequisites are missing.
- Build, run, export/load, registry, mount, networking and resource-control
  coverage, with interruption and failure injection.

Acceptance criteria:

- Required live tests demonstrably execute as root on supported hosts.
- Success, failed commands and interrupted operations leave no owned jails,
  mounts, build datasets, epairs, address leases or PF rules behind.
- Results identify the host release, architecture, storage mode and tested
  Legion dependency version.
- Fast unit and mock-based checks remain available independently.

Hosts: Legion's P0.1 needs the same disposable FreeBSD hosts, so one harness
should serve both. Until they exist, qualification runs on the shared test
host. That gives evidence, but does not meet "disposable", and arm64 is a VM.

Harness, agreed with Legion: one runner, `scripts/qualify` in Legion's repository,
fetched at the pinned tag, with a manifest per project and a JSON result per
run. Done here: `QUALIFY_REQUIRE_LIVE` makes what a jail test would skip fail
it, and `scripts/jailer.qualify` lists the jail tests, which `cargo test` now
reports as ignored.

Also close here the paths with no live coverage: the default `(self)` publish,
the address fix after a failed teardown, and `login` refusing a token realm
that is not https, which needs an https registry.

### Shared Jailer–Legion qualification

Extend qualification across the product boundary, using a recorded pair of
Jailer and Legion versions and their shared crate revisions. This is a
separate milestone from P0 above: the registry and offline routes need Legion's
P1.3, the stateful scenarios its P0.2, P1.2 and P1.4, so it does not hold P0
open.

- Build and test a native application with Jailer, sign and push its immutable
  digest, then deploy that exact image through Legion.
- Exercise both registry distribution and offline export followed by
  `legion image load`; verify image identity and application behavior survive
  each route, including gzip/zstd and multi-architecture index selection.
- Include a stateful fixture that writes identifiable data, drains to another
  node, and recovers after an interrupted migration. Assert image identity,
  data consistency and exclusive writer ownership separately.
- Record executed scenarios, failures and cleanup results. Shared crate reuse
  alone is not evidence that the full workflow passed.

Legion owns fencing, drain completion and migration recovery. Those are P0
platform safety dependencies for stateful qualification, not new Jailer
runtime responsibilities. Tests must expose duplicate-writer behavior rather
than presume that failure detection stopped the old process.

## P1.1 — Build-stage dependency planning

Build only stages needed by the selected target. Done on main: an unrelated
earlier stage containing `RUN false` no longer fails a later independent target.

Deliverables:

- Resolve dependencies through `FROM`, `COPY --from` and build-mount sources.
- Select the requested target, or final stage, and execute its required stage
  closure in a valid order.
- Preserve variable expansion, stage-name/index resolution and external-image
  behavior, with clear errors for invalid references.

Acceptance criteria:

- An unused failing stage does not affect an independent target.
- Dependencies through inherited stages, copies and mounts are built exactly
  when needed, including applicable base-image `ONBUILD` triggers.
- An unknown `--target` is reported before any stage runs.
- Existing cache, rootfs pinning and cleanup guarantees remain correct.
- Stage execution can remain sequential initially; parallelism is a later step.

Dependencies: existing multi-stage implementation. Planning is testable
without jails, so this runs alongside P0, which adds live regression evidence.

## P1.2 — Versioned compatibility contract

Make supported syntax and semantic differences discoverable before users depend
on a Containerfile working unchanged.

Deliverables:

- A support matrix for instructions, flags, parser directives, build contexts,
  platform arguments and cache formats.
- Explicit documentation of accepted syntax with reduced semantics, especially
  `COPY --link`, and ignored directives such as `# syntax=`.
- Focused differential fixtures against BuildKit/Buildah for applicable parser,
  copy, variable, stage and cache behavior. Exclude intentional OS differences
  from claims of equivalence.

Acceptance criteria:

- Every documented exception has a fixture or a concrete explanation.
- Unsupported behavior produces actionable errors or warnings.
- Registry-cache documentation explicitly describes Jailer's own format.
- Compatibility claims identify tested tool versions and platforms.

Dependencies: P1.1 for target-selection semantics only.

## P1.3 — Precise local-versus-Legion guarantees

Explain what local execution and static compatibility checks establish, and
where cluster-agent behavior adds guarantees.

Deliverables:

- Document per-process memory limits, networking defaults, probe handling and
  lifecycle differences between `jailer run` and a Legion deployment.
- Document the limits of `jailer check`; a passing static check is not proof
  that an application starts or remains healthy.
- Decide whether aggregate-memory enforcement belongs in local testing, with
  an explicit contract if it is introduced.

Acceptance criteria:

- A multiprocess memory fixture demonstrates current enforcement precisely.
- CLI help, man page and README agree on resource semantics.
- Shared runtime behavior is distinguished from agent-side enforcement and
  reconciliation behavior.

Dependencies: P0; coordination with Legion's resource-control contract.

## P1.4 — Immutable image handoff to Legion

Define one traceable image-identity contract from build through signing,
publication, deployment and recovery. This is the first slice of provenance;
full SBOM and attestation integration remains P2.1.

Deliverables:

- A versioned machine-readable build/release record containing source/context
  identity, resolved base-image digests, builder version, output manifest
  digest and platform. Exclude secret contents and credentials.
- Preserve the distinction between image-config, platform-manifest and index
  digests. For multi-architecture releases, record the index and its platform
  manifest mapping.
- Emit digest-qualified deployment references and signature-verification
  results bound to the same digest. Legion must enforce its configured trust
  policy at deployment; a Jailer-side verification alone is not admission.

Acceptance criteria:

- Moving a tag after publication does not change the image deployed,
  restarted or rolled back by the qualified workflow.
- The verified digest matches the deployed manifest; an index deployment
  records the selected platform manifest as well.
- Offline import preserves enough manifest identity and metadata to establish
  the same handoff. Document any signature/attestation transfer limitations.
- Failure to verify under a required policy prevents deployment, with an
  actionable result. This requires coordinated Legion work.

Dependencies: existing signing, registry and index support. The record,
references and verification results are Jailer's, and need only P0. The
deployment criteria above are joint: they close with shared qualification,
after Legion's P1.3 (immutable identities) and P2.1 (trust policy). The
release-record subset of structured output belongs here; broader CI
diagnostics remain P2.3.

## P2.1 — Provenance and SBOM integration

Extend existing signatures with evidence about image inputs and contents.

Deliverables:

- Record resolved base-image digests, source revision, builder version and
  relevant build inputs.
- Integrate standard provenance and SBOM attestations using established
  formats and tooling rather than a new cryptographic format.
- Validate FreeBSD package inventory coverage explicitly.

Acceptance criteria:

- Attestations identify the exact output image digest and remain associated
  with the correct platform image through publication.
- Standard consumers can retrieve and inspect the resulting metadata.
- Secret contents and credentials do not appear in attestations or logs;
  define and document build-argument disclosure policy.
- Missing scanner coverage is reported instead of represented as a complete
  inventory.

Dependencies: existing signing and registry/index support; P1.2 metadata
compatibility contract. Coordinate verification/admission policy with Legion.

## P2.2 — Remote native builds

Provide one developer workflow for builds on architecture-specific FreeBSD
hosts, building on the existing manifest publisher.

Deliverables:

- Coordinate native amd64 and arm64 builds on explicitly configured hosts.
- Transfer a defined build context and inputs, collect immutable result digests,
  and publish an index after all required builds succeed.
- Define cancellation, credentials, remote cleanup and partial-failure behavior.

Acceptance criteria:

- Each result's declared platform matches its intended builder and image.
- A failed architecture build does not publish a partially successful release
  under the requested final tag.
- Source/context identity is traceable across builders, and remote failures
  have actionable diagnostics.
- Existing manual per-host builds and `manifest push` remain usable.

Dependencies: P0 architecture qualification and existing index publication;
P2.1 improves input/output traceability. Emulation is not required for this
milestone.

## P2.3 — CI-friendly results and host diagnostics

Make failures easy for automation and users to interpret.

Deliverables:

- Structured compatibility-check and build results with stable finding codes,
  severity, output digests and clear exit-status semantics.
- Read-only host diagnostics covering relevant RACCT, PF anchors, forwarding,
  ZFS access and Linux ABI prerequisites. Legion's `legion doctor` (its P1.1)
  checks the same things: share them through a Legion crate, not a copy.

Acceptance criteria:

- Machine-readable output is parseable without scraping progress text.
- Diagnostics explain required versus optional prerequisites for the requested
  operation and do not modify host configuration.
- Existing checks and system abstractions are reused where practical.

Dependencies: P1.3 for precise claims about runtime requirements and behavior.

## P3 — Parallel stage execution

Execute independent stages concurrently once dependency planning and cleanup
are proven.

Acceptance criteria:

- Concurrency is bounded and respects dependencies and cache-mount sharing.
- Cancellation and stage failure clean up all running work and owned resources.
- Parallel and sequential builds produce equivalent outputs for deterministic
  fixtures.
- Benchmarks demonstrate gains for representative FreeBSD projects and report
  resource costs; avoid unsupported performance rankings.

Dependencies: P1.1 and P0; validate shared store/cache synchronization first.

## Scope and sequencing

| Phase | Work | Waits on |
|---|---|---|
| 1. Honest tests | P0: required live runs, a recorded qualification script, ZFS and plain-directory storage, the uncovered paths | Nothing; hosts for the full matrix |
| 2. Stage planning | P1.1 | Nothing; runs alongside phase 1 |
| 3. Stated guarantees | P1.2, P1.3: done, in `docs/` and `tests/compat` | Phase 2 for target semantics |
| 4. Image handoff | P1.4's Jailer side, with structured `check` output: done, in `docs/RELEASE-RECORD.md` | Phase 1 |
| 5. Shared qualification | Build to Recover across both products; P1.4's joint criteria | Legion P1.3, P0.2, P1.2, P1.4, P2.1 |
| 6. Supply chain and automation | P2.1, P2.2, P2.3 | Phases 1 and 4; a shared diagnostics crate |
| 7. Parallel stages | P3 | Phases 1 and 2 |

Use Build → Sign → Push → Deploy → Drain → Migrate → Recover as the shared
engineering contract. Test each boundary while retaining clear ownership:
Jailer builds and tests artifacts; Legion deploys and operates workloads;
FreeBSD supplies kernel, storage and networking primitives. Track capability
coverage with named scenarios and acceptance evidence rather than unmeasured
percentage-parity estimates.

Rootless jail execution is an architectural limitation, not a missing CLI
flag. General service management, cluster scheduling and boot-time restart
policies remain outside this roadmap. Linux ABI opt-in must not be described
as general Linux kernel compatibility.

## Review evidence and comparison references

- `src/build.rs`: sequential stage execution, host-platform arguments,
  platform rejection, timestamp controls and post-build checks.
- `src/containerfile.rs`: parser directives and instruction/flag handling.
- `src/cache.rs`: Jailer registry-cache configuration and lazy layer import.
- `src/runtime.rs`: local run specification and per-process memory limits.
- `src/sign.rs`: digest-bound P-256 simple-signing payloads.
- `src/check.rs`: static compatibility findings.
- `tests/freebsd_jail_test.rs`: FreeBSD-only privileged workflow tests.
- `scripts/freebsd-build.sh`: source transfer and remote Cargo invocation.
- [BuildKit execution model](https://docs.docker.com/build/buildkit/)
- [Docker multi-platform build strategies](https://docs.docker.com/build/building/multi-platform/)
- [Build attestations](https://docs.docker.com/build/metadata/attestations/)
- [Buildah build reference](https://github.com/podman-container-tools/buildah/blob/main/docs/buildah-build.1.md)
