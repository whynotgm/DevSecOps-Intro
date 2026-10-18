# Lab 12 — runc baseline and Kata isolation analysis

**Status: partial execution, 2026-10-18.** The Docker `runc` baseline and privileged bind-mount demonstration below were executed. **Kata was not run:** this Mac's Docker Desktop Linux VM exposes no `/dev/kvm`; installing userspace runtime binaries cannot supply the missing KVM device. There is no Kata guest kernel, startup median, I/O figure, memory measurement or escape-test outcome to report. This report does not meet the full two-runtime acceptance criteria until the Linux collector is run on a KVM-capable machine.

Artifacts: [`docker-baseline.py`](../labs/lab12/scripts/docker-baseline.py) reproduces the available Docker measurements. [`collect.py`](../labs/lab12/scripts/collect.py) collects the complete comparison on prepared Linux, including raw command output, host process memory and an optional privileged test. Raw local evidence is in ignored `labs/lab12/results/`; the measured values needed for review are reproduced here.

## Task 1

### Environment and actual prerequisites

```console
$ uname -r
25.5.0
$ docker info --format '{{.OSType}} {{.Architecture}}'
linux aarch64
$ docker run --rm --privileged alpine:3.20 sh -c 'uname -r; ls -l /dev/kvm'
7.0.12-linuxkit
ls: /dev/kvm: No such file or directory
# Exit 1
```

`docker info` lists only `runc` and its `io.containerd.runc.v2` alias, with runc **1.4.3**. The container host is Docker's Linux VM (**7.0.12-linuxkit**), not the macOS Darwin kernel (**25.5.0**). A privileged Docker container still has no KVM device: `--privileged` grants access to existing facilities, not hardware virtualization capabilities absent from that VM.

The pinned intended Kata version is **4.1.0** from the supplied installer. **No Kata version was installed or measured.** Neither `containerd` nor `nerdctl` is installed on the macOS host; Docker manages its own containerd inside the VM.

### Unprivileged Alpine 3.20 comparison

Commands executed:

```bash
docker run --rm --runtime=runc alpine:3.20 uname -r
docker run --rm --runtime=runc alpine:3.20 sh -c 'ls -1 /dev | wc -l'
docker run --rm --runtime=runc alpine:3.20 sh -c 'grep ^CapEff /proc/1/status'
```

| Measurement | Docker runc, observed | Kata |
|---|---|---|
| Linux host kernel | `7.0.12-linuxkit` | Same host required for a fair comparison |
| Container kernel | `7.0.12-linuxkit` | Not measured: KVM unavailable |
| `/dev` entries | **15** | Not measured |
| `CapEff` | `00000000a80425fb` | Not measured |

The matching `uname -r` output identifies the exact Linux kernel release shared by the container and Docker VM, helping an attacker select candidate kernel vulnerabilities and exploit prerequisites. It does not prove any particular vulnerability is exploitable: distribution patches, configuration, seccomp and capabilities still matter. Under Kata, that line identifies the guest kernel instead; gaining control of it still leaves a virtualization boundary before the host. A different release is useful evidence but not a proof of isolation by itself; corroborate the runtime selection and VM processes.

## Task 2

### Measured Docker startup and I/O

The image was already local. The collector discarded one warm-up, then timed five `docker run --rm --runtime=runc alpine:3.20 true` executions with Python's monotonic `perf_counter`; creation, process execution and deletion are included. These are **Docker CLI/daemon measurements**, not the lab's `nerdctl` timings, and must not be combined with a future Kata run through a different frontend.

| Runtime/frontend | Run 1 (s) | Run 2 (s) | Run 3 (s) | Run 4 (s) | Run 5 (s) | Median (s) |
|---|---:|---:|---:|---:|---:|---:|
| Docker runc | 0.173248 | 0.165932 | 0.157013 | 0.178414 | 0.167233 | **0.167233** |
| Kata | — | — | — | — | — | Not measured |

```console
$ docker run --rm --runtime=runc alpine:3.20 \
    sh -c 'dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync'
512+0 records in
512+0 records out
536870912 bytes (512.0MB) copied, 0.216844 seconds, 2.3GB/s
```

Writing a file crosses the container storage layer and `fsync` requests completion of buffered writes; `/dev/null` discards the data and would bypass that comparison. This is one sequential write sample on Docker Desktop storage, not an application benchmark or a durable-device guarantee independent of the VM's storage stack. Kata throughput remains unmeasured.

### Memory and its limits

An Alpine `sleep 120` container reported **1.965 MiB / 7.748 GiB** through `docker stats --no-stream --format '{{json .}}'`. This is the container's accounted usage, **not total per-container runtime overhead**: it excludes shared Docker/containerd costs and cannot establish the cost of a guest kernel or hypervisor. Accordingly, neither a Kata overhead nor a runc-versus-Kata memory delta is claimed.

On a prepared Linux host, `collect.py` starts one sleeping container per runtime, waits three seconds, then takes five samples of **host PSS** from the dedicated containerd shim and all its descendants. It sums `/proc/<pid>/smaps_rollup` PSS, recording every PID and command, and reports the median in KiB; for Kata this includes the hypervisor/guest RAM and virtiofs processes when they are descendants of that shim. This measures the dedicated runtime process tree including the workload, excluding the shared containerd daemon and filesystem page-cache costs not mapped into those processes; the difference between the two medians estimates additional resident sandbox cost. The collector rejects a missing or ambiguous shim rather than silently reporting zero memory. **This Linux memory method has been implemented and syntax-checked, but not executed in this environment.**

### Workload choices

| Workload | Verdict | Reason |
|---|---|---|
| Trusted, high-volume Juice Shop-like web service with controlled images | `runc` | Familiar operations and low startup/memory cost are reasonable with hardening and prompt host patching. |
| Long-running workers that execute untrusted tenant code | Kata | A separate guest kernel adds a valuable boundary while VM startup is amortized over long jobs. |
| Latency-sensitive, short-lived functions with heavy filesystem access | Needs more information | Measure cold-start targets, concurrency, storage behavior and syscall compatibility; gVisor or a tuned microVM platform may also fit. |

No measured order-of-magnitude startup gap exists in this environment because Kata could not run. If a completed comparison shows such a gap, it matters little for workers or services running for hours or days: an extra second at creation is amortized over millions of operations. Steady-state CPU, memory, I/O and tail latency then determine capacity more strongly. It can still matter during large autoscaling events and recovery, so long lifetime alone does not remove every operational effect.

## Bonus

### Observed privileged write

The collector creates a fresh temporary directory on the Mac and mounts **only that directory** rather than exposing all of `/tmp`. The directory and target file are deleted after the test. This preserves the lab's write-through-bind-mount vector while limiting its scope.

```bash
# Collector created /tmp/lab12-aup51hkc/lab12-target containing "original".
docker run --rm --runtime=runc --privileged \
  -v /tmp/lab12-aup51hkc:/host_tmp alpine:3.20 \
  sh -c 'echo OVERWRITTEN > /host_tmp/lab12-target'
# Exit 0; read back on the Mac: OVERWRITTEN

docker run --rm --runtime=runc --privileged alpine:3.20 \
  sh -c 'ls -1 /dev | wc -l; grep ^CapEff /proc/1/status'
# 169
# CapEff: 000001ffffffffff
```

| Runtime | Original host file | Host file after command | Privileged `/dev` entries | Privileged CapEff |
|---|---|---|---:|---|
| Docker runc | `original` | **`OVERWRITTEN`**, exit 0 | **169** | `000001ffffffffff` |
| Kata | Not run | Not measured | Not measured | Not measured |

### Interpretation, including the bind-mount caveat

`--privileged` greatly increases capabilities and device access relative to the observed 15 devices and `a80425fb` mask; under runc those privileges concern the shared Linux VM kernel. A writable host bind mount is an explicitly granted path to host data, and writing it does not require a kernel escape or even necessarily `--privileged`. Under Kata, privileged operations concern the guest kernel and its exposed devices, but an intentionally shared writable host directory can still permit host-file modification through the filesystem sharing mechanism. Therefore **this bind-mount example is not guaranteed to be stopped by Kata**; the pending Kata test must report whether the write succeeds, fails or is rejected at startup, rather than infer the result from the lab title. The [Kata architecture and storage documentation](https://github.com/kata-containers/kata-containers/tree/main/docs/design/architecture) describes the guest and filesystem-sharing boundaries that inform this expectation.

Kata does not protect host data that an operator deliberately exports as a writable mount, nor fix application authorization flaws.

## Completing the missing measurements on Linux

Run on a disposable Linux machine with functional `/dev/kvm`, containerd, nerdctl, CNI and Python 3. Read all three supplied setup scripts before using sudo; the optional from-source build is not needed for the pinned static installation.

```bash
ls -l /dev/kvm
command -v containerd nerdctl python3
# Save the existing containerd configuration before modifying it.
sudo cp -a /etc/containerd/config.toml /etc/containerd/config.toml.pre-lab12
sudo bash labs/lab12/scripts/install-kata-assets.sh 4.1.0
# Ensure containerd's service PATH can locate /opt/kata/bin/containerd-shim-kata-v2.
# If a shim symlink/configuration is needed, set it up for the installed architecture.
sudo bash labs/lab12/scripts/configure-containerd-kata.sh
sudo containerd --config /etc/containerd/config.toml config dump
sudo systemctl restart containerd
sudo env PATH="/opt/kata/bin:$PATH" python3 labs/lab12/scripts/collect.py --bonus
```

The collector preflights the host before changing anything, pulls the same Alpine image once, uses **explicit runtime names**, warms up both runtimes, captures five startup times and medians, captures file-write throughput, measures host PSS, and runs identical privileged commands with only the runtime changed. It writes `submissions/lab12-measurements.md` and raw JSON/command logs; merge the actual outcomes and version metadata into this report before submission. Failed commands are saved and surfaced rather than interpreted as benchmark results. Re-run both runtimes on the same Linux machine; the current Mac baseline is supplementary only.

For cleanup on that disposable machine, remove only lab containers, restore the saved containerd configuration, validate it, restart containerd, and remove the Kata assets/configuration/symlinks introduced for the lab after checking they were not pre-existing. No Kata installer or containerd reconfiguration was executed on this Mac.
