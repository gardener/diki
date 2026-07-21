# Pod Security Standards Guide

## Introduction

The Pod Security Standards ruleset checks pods running in a Kubernetes cluster against the official [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/). It implements both the **Baseline** and **Restricted** profiles as individual rules, enabling fine-grained compliance checking and reporting.

- The **Baseline** profile (rules PSS-B001 to PSS-B012) prevents known privilege escalations and is minimally restrictive.
- The **Restricted** profile (rules PSS-R001 to PSS-R006) enforces current pod hardening best practices.

The version documented here is [v0.1.0](pod-security-standards-v0.1.0.yaml).

## Baseline Profile

The Baseline profile prevents known privilege escalations. Targeted at application operators and developers of non-critical applications.

---

### PSS-B001 - HostProcess <a id="PSS-B001"></a>

#### Description
Windows Pods offer the ability to run HostProcess containers which enables privileged access to the Windows host machine. Privileged access to the host is disallowed in the Baseline policy.

#### Fix
Do not set `securityContext.windowsOptions.hostProcess` to `true` at the pod or container level.

---

### PSS-B002 - Host Namespaces <a id="PSS-B002"></a>

#### Description
Sharing the host namespaces must be disallowed.

#### Fix
Do not set `spec.hostNetwork`, `spec.hostPID`, or `spec.hostIPC` to `true`.

---

### PSS-B003 - Privileged Containers <a id="PSS-B003"></a>

#### Description
Privileged Pods disable most security mechanisms and must be disallowed.

#### Fix
Do not set `securityContext.privileged` to `true` on any container.

---

### PSS-B004 - Capabilities (Baseline) <a id="PSS-B004"></a>

#### Description
Adding additional capabilities beyond the following must be disallowed: `AUDIT_WRITE`, `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `MKNOD`, `NET_BIND_SERVICE`, `SETFCAP`, `SETGID`, `SETPCAP`, `SETUID`, `SYS_CHROOT`.

#### Fix
Remove any capabilities from `securityContext.capabilities.add` that are not in the allowed set.

---

### PSS-B005 - HostPath Volumes <a id="PSS-B005"></a>

#### Description
HostPath volumes must be forbidden.

#### Fix
Remove any `Volumes` of type `hostPath` from the `Pod` spec.

---

### PSS-B006 - Host Ports <a id="PSS-B006"></a>

#### Description
HostPorts should be disallowed entirely (recommended) or restricted to a known list.

#### Fix
Remove `hostPort` from container port definitions or set it to `0`.

---

### PSS-B007 - Host Probes / Lifecycle Hooks <a id="PSS-B007"></a>

#### Description
The host field in probes and lifecycle hooks must be disallowed. Setting the `host` field in `httpGet` probes or lifecycle hooks allows a container to send requests to arbitrary hosts, bypassing network policies.

#### Fix
Do not set the `host` field in `httpGet` probes (`livenessProbe`, `readinessProbe`, `startupProbe`) or lifecycle hooks (`postStart`, `preStop`).

---

### PSS-B008 - AppArmor <a id="PSS-B008"></a>

#### Description
On supported hosts, the `RuntimeDefault` AppArmor profile is applied by default. The Baseline policy should prevent overriding or disabling the default AppArmor profile, or restrict overrides to an allowed set of profiles.

#### Fix
Do not set `securityContext.appArmorProfile.type` to `Unconfined` at the pod or container level.

---

### PSS-B009 - SELinux <a id="PSS-B009"></a>

#### Description
Setting the SELinux type is restricted, and setting a custom SELinux user or role option is forbidden. Allowed types: (empty), `container_t`, `container_init_t`, `container_kvm_t`.

#### Fix
Do not set `seLinuxOptions.type` to a value outside the allowed set. Remove the field or use one of the allowed types.

---

### PSS-B010 - /proc Mount Type <a id="PSS-B010"></a>

#### Description
The default `/proc` masks are set up to reduce attack surface, and should be required.

#### Fix
Do not set `securityContext.procMount` or set it explicitly to `Default`.

---

### PSS-B011 - Seccomp (Baseline) <a id="PSS-B011"></a>

#### Description
Seccomp profile must not be explicitly set to `Unconfined`.

#### Fix
Do not set `securityContext.seccompProfile.type` to `Unconfined` at the pod or container level.

---

### PSS-B012 - Sysctls <a id="PSS-B012"></a>

#### Description
Sysctls can disable security mechanisms or affect all containers on a host, and should be disallowed except for an allowed "safe" subset. A sysctl is considered safe if it is namespaced in the container or the Pod, and it is isolated from other Pods or processes on the same Node. Allowed: `kernel.shm_rmid_forced`, `net.ipv4.ip_local_port_range`, `net.ipv4.ip_unprivileged_port_start`, `net.ipv4.tcp_syncookies`, `net.ipv4.ping_group_range`, `net.ipv4.ip_local_reserved_ports`, `net.ipv4.tcp_keepalive_time`, `net.ipv4.tcp_fin_timeout`, `net.ipv4.tcp_keepalive_intvl`, `net.ipv4.tcp_keepalive_probes`.

#### Fix
Remove any sysctls that are not in the allowed set from `spec.securityContext.sysctls`.

---

## Restricted Profile

The Restricted profile enforces current pod hardening best practices, at the expense of some compatibility. It includes all Baseline requirements plus the following additional restrictions.

---

### PSS-R001 - Volume Types <a id="PSS-R001"></a>

#### Description
The Restricted policy only permits the following volume types: `configMap`, `csi`, `downwardAPI`, `emptyDir`, `ephemeral`, `persistentVolumeClaim`, `projected`, `secret`.

#### Fix
Restrict `Pod` volume types to `configMap`, `csi`, `downwardAPI`, `emptyDir`, `ephemeral`, `persistentVolumeClaim`, `projected` and `secret`.

---

### PSS-R002 - Privilege Escalation <a id="PSS-R002"></a>

#### Description
Privilege escalation (such as via set-user-ID or set-group-ID file mode) should not be allowed. This is Linux only policy in v1.25+.

#### Fix
Set `securityContext.allowPrivilegeEscalation` to `false` on every container.

``` yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: ...
    securityContext:
      allowPrivilegeEscalation: false
  initContainers:
  - name: ...
    securityContext:
      allowPrivilegeEscalation: false
```
---

### PSS-R003 - Running as Non-root <a id="PSS-R003"></a>

#### Description
Containers must be required to run as non-root users.

#### Fix
Set `runAsNonRoot: true` at the pod level or on each container. Container-level settings override pod-level.

``` yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
  containers:
  - name: ...
    securityContext:
      runAsNonRoot: true
```
---

### PSS-R004 - Running as Non-root user <a id="PSS-R004"></a>

#### Description
Containers must not set `runAsUser` to 0.

#### Fix
Do not set `runAsUser` to `0`. Set it to a non-zero value or omit it.

---

### PSS-R005 - Seccomp (Restricted) <a id="PSS-R005"></a>

#### Description
Seccomp profile must be explicitly set to `RuntimeDefault` or `Localhost`. Unconfined profiles and the absence of a profile are prohibited.

#### Fix
Set `securityContext.seccompProfile.type` to `RuntimeDefault` or `Localhost` at the pod level or on each container.

``` yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: ...
    securityContext:
      seccompProfile:
        type: RuntimeDefault
```
---

### PSS-R006 - Capabilities (Restricted) <a id="PSS-R006"></a>

#### Description
Containers must drop `ALL` capabilities, and are only permitted to add back `NET_BIND_SERVICE`.

#### Fix
Set `capabilities.drop` to include `ALL` and only add `NET_BIND_SERVICE` if required.

``` yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: ...
    securityContext:
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
```
