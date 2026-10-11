# Lab 9 — Runtime Detection and Policy as Code

Executed **2026-10-11**, macOS arm64, Docker Desktop (Linux VM), Falco **0.43.1**, Conftest **0.69.0**. Both tasks and the mining bonus were executed. Raw logs and validation output remain in ignored `labs/lab9/falco/logs/`; the alert JSON below was captured from this run.

## Task 1

### Setup and built-in alerts

The supplied `/boot` mount was rejected by Docker Desktop file sharing. Modern eBPF is bundled in Falco, so I omitted the unneeded `/boot`, `/lib/modules` and `/usr` mounts and shared the Linux VM's process namespace instead. This monitors Docker's **Linux VM**, not macOS processes. Contrary to the lab's blanket Desktop limitation, this VM exposes sufficient kernel facilities for these detections; the successful alerts establish that directly. Falco stayed running despite the documented TOCTOU tracepoint warnings.

```bash
docker run -d --name lab9-falco --privileged --pid=host \
  -v /proc:/host/proc:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$PWD/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:0.43.1 \
  falco -U -o json_output=true -o time_format_iso_8601=true
docker run -d --name lab9-target alpine:3.20 sleep 1d
# Wait for Falco's event capture to initialize before running triggers.
docker exec -t lab9-target /bin/sh -c 'echo hello-from-shell; sleep 2'
docker exec lab9-target sh -c 'cat /etc/shadow'
```

`Terminal shell in container` fired on `execve` of a shell with a terminal; `proc.tty=34816` confirms the attached terminal. The initial fast shell was missed during initialization, so I repeated it after the probe was ready. Captured alert:

```json
{
  "hostname": "793bf3cae33d",
  "output": "2026-10-11T10:14:33.634814012+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -c echo hello-from-shell; sleep 2 terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=ed04e95161e5 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "ed04e95161e5",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.arg.flags": "EXE_WRITABLE|EXE_LOWER_LAYER",
    "evt.time.iso8601": 1791713673634814012,
    "evt.type": "execve",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -c echo hello-from-shell; sleep 2",
    "proc.exepath": "/bin/busybox",
    "proc.name": "sh",
    "proc.pname": "containerd-shim",
    "proc.tty": 34816,
    "user.loginuid": -1,
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "source": "syscall",
  "tags": [
    "T1059",
    "container",
    "maturity_stable",
    "mitre_execution",
    "shell"
  ],
  "time": "2026-10-11T10:14:33.634814012Z"
}
```

`Read sensitive file untrusted` fired when `cat` opened `/etc/shadow` for reading. Captured alert:

```json
{
  "hostname": "793bf3cae33d",
  "output": "2026-10-11T10:13:17.687940684+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=initd ggparent=<NA> gggparent=<NA> evt_type=openat user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=ed04e95161e5 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "ed04e95161e5",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1791713597687940684,
    "evt.type": "openat",
    "fd.name": "/etc/shadow",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.aname[2]": "initd",
    "proc.aname[3]": null,
    "proc.aname[4]": null,
    "proc.cmdline": "cat /etc/shadow",
    "proc.exepath": "/bin/busybox",
    "proc.name": "cat",
    "proc.pname": "containerd-shim",
    "proc.tty": 0,
    "user.loginuid": -1,
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "source": "syscall",
  "tags": [
    "T1555",
    "container",
    "filesystem",
    "host",
    "maturity_stable",
    "mitre_credential_access"
  ],
  "time": "2026-10-11T10:13:17.687940684Z"
}
```

### Custom write rule

Rule file: [`custom-rules.yaml`](../labs/lab9/falco/rules/custom-rules.yaml). The first rule uses the shipped `open_write` macro, excludes `container.id=host`, and matches `/tmp/` paths. `open_write` observes successful opens with write access, rather than every individual `write(2)` or bytes actually written; a process opening an existing descriptor before monitoring could escape this rule. That is the lab's proposed write-detection signal, and an important scope limitation.

```bash
docker exec lab9-falco falco \
  -V /etc/falco/falco_rules.yaml \
  -V /etc/falco/rules.d/custom-rules.yaml
docker kill --signal=SIGHUP lab9-falco
# Wait until the rules have reloaded.
docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'
```

Validation exited **0**. The mining rule's `evt.dir=<` produced a deprecation warning because current Falco captures exit events only; it remains valid and follows the lab's requested syntax. Validation must load **both** files with `-V`: validating the custom file alone cannot resolve `open_write` from the defaults. Captured custom alert:

```json
{
  "hostname": "793bf3cae33d",
  "output": "2026-10-11T10:14:35.685195513+0000: Warning Container opened tmp file for writing (container=lab9-target user=root file=/tmp/my-write.txt command=sh -lc echo test > /tmp/my-write.txt) container_id=ed04e95161e5 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "ed04e95161e5",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1791713675685195513,
    "fd.name": "/tmp/my-write.txt",
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
    "user.name": "root"
  },
  "priority": "Warning",
  "rule": "Container Write Under Tmp",
  "source": "syscall",
  "tags": [
    "container",
    "drift"
  ],
  "time": "2026-10-11T10:14:35.685195513Z"
}
```

The JSON `hostname="793bf3cae33d"` identifies the Falco sensor and is absent from the human-readable `output`. During an incident, mapping that sensor to its monitored node distinguishes identical container names on different hosts and guides evidence collection.

A legitimate image-processing worker creates temporary files under `/tmp` for every request and would trigger this rule repeatedly. I would add a narrowly scoped exception combining its approved image digest, executable and dedicated temporary subdirectory, rather than exempting all `/tmp` activity for the whole container. Unexpected executables, paths or image versions would still alert. Rate-limit repeated expected events in the alert pipeline while retaining raw events for investigation.

## Task 2

### Shipped policy results

Commands used Conftest 0.69.0 with `--policy labs/lab9/policies --all-namespaces --output json` before adding the extra rules:

| Input | Successes | Failures | Warnings | Exit |
|---|---:|---:|---:|---:|
| Kubernetes hardened | 30 | 0 | 0 | 0 |
| Kubernetes unhardened | 20 | 8 | 2 | 1 |
| Compose | 15 | 0 | 0 | 0 |

These are Conftest evaluation counts, not vulnerability totals: the hardened Kubernetes YAML contains a Deployment and a Service, and `--all-namespaces` also evaluates policies that are irrelevant to that input.

All eight failures map to `k8s.security.deny` in `k8s-security.rego`:

| Failure | Rule condition |
|---|---|
| Uses `:latest` | `endswith(c.image, ":latest")` |
| Must set runAsNonRoot | `not c.securityContext.runAsNonRoot` |
| Must disable privilege escalation | `not c.securityContext.allowPrivilegeEscalation == false` |
| Must use a read-only root filesystem | `not c.securityContext.readOnlyRootFilesystem == true` |
| Missing CPU request | `not c.resources.requests.cpu` |
| Missing memory request | `not c.resources.requests.memory` |
| Missing CPU limit | `not c.resources.limits.cpu` |
| Missing memory limit | `not c.resources.limits.memory` |

The missing readiness/liveness probes map to the two `k8s.security.warn` rules. The unhardened example already drops ALL capabilities, so that check does not fail.

Compose and Kubernetes need separate rules because the equivalent control lives in different schemas (`services[].read_only` versus the Deployment container's `securityContext.readOnlyRootFilesystem`). The Compose pass is a positive control showing that compliant input is accepted, although it proves only the encoded requirements, not general application security.

### Additional policy and deliberate violation

Policy: [`extra/hardening.rego`](../labs/lab9/policies/extra/hardening.rego), package `k8s.extra`. The deny requires an immutable SHA-256 image digest; the warn catches explicitly sharing the host network namespace. Both messages name the container. The shipped policy checks neither of these requirements.

Fixture: [`violates-extra-policy.yaml`](../labs/lab9/manifests/k8s/violates-extra-policy.yaml). It preserves the hardened container controls and probes, but uses a version tag and sets `hostNetwork: true`, isolating the two new checks.

```bash
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml \
  --policy labs/lab9/policies --all-namespaces
conftest test labs/lab9/manifests/k8s/violates-extra-policy.yaml \
  --policy labs/lab9/policies --all-namespaces
```

Hardened: **34 successes, 0 failures, 0 warnings, exit 0**.

Violation fixture: **15 successes, 1 failure, 1 warning, exit 1**:

```text
FAIL - k8s.extra - container "juice" must pin its image by SHA-256 digest
WARN - k8s.extra - container "juice" should not share the host network namespace
```

If I could retain only one control for image immutability, I would keep Conftest in CI because it rejects a mutable tag before that manifest is deployed. The same check should also run at admission, because CI can be bypassed. Runtime monitoring still detects unexpected execution and file/network activity after a trusted artifact is compromised, but a syscall detector cannot by itself prove that a manifest originally used a digest. Digest pinning fixes identity, not vulnerabilities; signatures and trusted provenance add separate evidence.

## Bonus

The second rule in `custom-rules.yaml` combines a miner-like process name with an attempted outbound connection to one of five common pool ports; its priority is CRITICAL and its tags include `mitre_command_and_control`.

Alpine's `nc` initially resolved to BusyBox, which interprets an executable renamed `xmrig` as an unknown applet. I installed the standalone netcat package and copied that executable under a miner-like name. This is a harmless simulation, not a miner, and contacts only loopback:

```bash
docker exec lab9-target apk add --no-cache netcat-openbsd
docker exec lab9-target sh -c 'cp /usr/bin/nc /tmp/xmrig'
docker exec lab9-target sh -c '/tmp/xmrig -w 2 127.0.0.1 3333' || true
```

Captured alert:

```json
{
  "hostname": "793bf3cae33d",
  "output": "2026-10-11T10:14:20.832220714+0000: Critical Likely mining connection (container=lab9-target process=xmrig command=xmrig -w 2 127.0.0.1 3333 destination=127.0.0.1:3333 result=EINPROGRESS) container_id=ed04e95161e5 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "ed04e95161e5",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.res": "EINPROGRESS",
    "evt.time.iso8601": 1791713660832220714,
    "fd.sip": "127.0.0.1",
    "fd.sport": 3333,
    "k8s.ns.name": null,
    "k8s.pod.name": null,
    "proc.cmdline": "xmrig -w 2 127.0.0.1 3333",
    "proc.name": "xmrig"
  },
  "priority": "Critical",
  "rule": "Likely Container Mining Connection",
  "source": "syscall",
  "tags": [
    "container",
    "mitre_command_and_control"
  ],
  "time": "2026-10-11T10:14:20.832220714Z"
}
```

A successful TCP session is unnecessary: Falco observes the process's `connect` syscall and attempted destination in the kernel. This particular nonblocking netcat invocation reported **EINPROGRESS** at syscall return; the alert is not evidence of a completed connection or an `ECONNREFUSED` return. A follow-up run with `-v` printed `Connection refused` and exited **1**. Ordinary `/usr/bin/nc` on the same port produced no mining alert; both captured mining alerts named `xmrig`. There was no pool/server listening on the target loopback port. Falco sits below the application's protocol handling, so even attempts that never establish a session are visible.

Changing the port or renaming the executable is cheap; **neither signal in this simple rule is expensive to evade**. Sustaining profitable mining still needs substantial compute and some way to receive work/submit results, which is harder to conceal completely, though an attacker can proxy it over ordinary ports. I would correlate CPU use, binary provenance, new executable activity, destinations and Stratum-like traffic where observable. TLS obscures payload inspection, so maintain egress allowlists and anomaly detection rather than assuming port-based coverage.

## Cleanup

After collecting alerts, remove only the two lab containers with `docker rm -f lab9-falco lab9-target`. Rules, policies, the violating fixture and this report are the public deliverables. See [Falco container deployment](https://falco.org/docs/setup/container/) for the bundled modern eBPF probe and kernel access requirements.
