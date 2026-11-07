# Local runs and Legion

`jailer run` starts a container with the same `legion-jail` code a Legion node
uses, so a jail's parameters, security defaults, mounts and user handling are
the same. It does not run Legion's agent. What the agent adds on a node has no
equivalent locally, so a good local run says less than a good deployment.

| | `jailer run` | A Legion node |
|---|---|---|
| Jail creation, `devfs`, security defaults | `legion-jail` | `legion-jail` |
| Image store and layers | `legion-image` | `legion-image` |
| Memory limit | Each process | Each process, and the container's total |
| CPU, process limits | rctl rules on the jail | rctl rules on the jail |
| Open-file limit | None | rctl rule on the jail |
| CPU sets | `--cpuset-cpus` | Not offered for pods |
| Network by default | The host's | A pod on the node's bridge |
| Bridge | `--vnet`: `jailer0`, 10.77.0.0/16 or `--pod-subnet`'s, IPv4 only | Legion's own |
| Published ports | `-p`, through pf anchors under `jailer/` | Services, and Legion's load balancing |
| Health | None: `HEALTHCHECK` is not kept | Startup, liveness and readiness probes |
| Restart | None: a container that stops stays stopped | Restart policy, with delay and attempts |
| After a host restart | Nothing comes back | Reconciled to the desired state |
| Scheduling, service discovery, rollout, drain | None | Legion's |

## Memory

`-m` is an rctl rule that kills a process whose own resident memory passes the
limit. It does not hold a container's total: many processes under the limit may
together use far more, and none is killed.

A Legion node has the same rule and also measures the container's whole memory,
counting shared pages once, and kills its largest process when the total is
over. So a container that fits under `-m` locally can still lose a process on a
node with the same limit. The test `memory_limits_each_process_not_the_container`
shows jailer's side of this.

`jailer run` will not add that total. It lives in Legion's agent, and a local
copy could drift from it. If it moves to a shared crate, jailer can use it there.

## What `jailer check` proves

`jailer check` reads the Containerfile, or the image's config and files, for
what would fail on a node. It finds:

- a `USER` not in the image's `/etc/passwd` and `/etc/group`
- a command or working directory not in the image
- an image with neither `ENTRYPOINT` nor `CMD`
- a `STOPSIGNAL` Legion does not know
- an OS or architecture Legion does not run, and images needing `--linux`
- `HEALTHCHECK`, and `pkg` caches left in a layer

It runs nothing. A clean check does not show that the application starts, that it
stays healthy, or that it fits its limits. For that, use `jailer run`, and then
a Legion deployment.
