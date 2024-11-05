# Security Hardened Kubernetes Cluster Guide

## Introduction

The Security Hardened Kubernetes Cluster Guide is created as an extension to the [DISA Kubernetes Security Technical Implementation Guide](../disa-k8s-stig/ruleset.md).
It aims to additionally increase the security posture of a Kubernetes cluster.
The ruleset is inspired and follows some of the policies from [Kyverno](https://release-1-12-0.kyverno.io/policies/).

## Rules

### 2000 - Ingress and egress traffic must be restricted by default.

#### Description
This rule follows the requirements from Kyverno best practices policy [Add Network Policy](https://release-1-12-0.kyverno.io/policies/best-practices/add-network-policy/add-network-policy/).

#### Fix
Configure a default `NetworkPolicy` for each `Namespace` to default deny all ingress and egress traffic to the `Pods` in the `Namespace`.

``` yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
spec:
  # select all pods in the namespace
  podSelector: {}
  # deny all traffic
  policyTypes:
  - Ingress
  - Egress
```
---

### 2001 - Containers must be forbidden to escalate privileges.

#### Description
This rule follows the requirements from Kyverno pod security policy [Disallow Privilege Escalation](https://release-1-12-0.kyverno.io/policies/pod-security/restricted/disallow-privilege-escalation/disallow-privilege-escalation/).

#### Fix
Do not set `Pod` container fields `securityContext.allowPrivilegeEscalation` as it defaults to `false` or set it explicitly to `false`.

> [!WARNING]  
> `securityContext.allowPrivilegeEscalation` is set to `true` in the following exceptions:
> - container is running as `privileged`
> - `CAP_SYS_ADMIN` is added to the container

``` yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: ...
    securityContext:
      allowPrivilegeEscalation: false
```
---

### 2002 - Storage Classes should have a "Delete" reclaim policy.

#### Description
This rule follows the requirements from Kyverno policy [Restrict StorageClass](https://release-1-12-0.kyverno.io/policies/other/restrict-storageclass/restrict-storageclass/).

#### Fix
Do not set `StorageClass` field `reclaimPolicy` as it defaults to `Delete` or set it explicitly to `Delete`.

``` yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
reclaimPolicy: Delete
```
---

### 2003 - Pods should use only allowed volume types.

#### Description
This rule follows the requirements from Kyverno pod security policy [Restrict Volume Type](https://release-1-12-0.kyverno.io/policies/pod-security/restricted/restrict-volume-types/restrict-volume-types/).

#### Fix
`Pod` `Volume` types are restricted to `configMap`, `csi`, `downwardAPI`, `emptyDir`, `ephemeral`, `persistentVolumeClaim`, `projected` and `secret`.

---

### 2004 - Limit the Services of type NodePort.

#### Description
This rule follows the requirements from Kyverno best practices policy [Disallow NodePort](https://release-1-12-0.kyverno.io/policies/best-practices/restrict-node-port/restrict-node-port/).

#### Fix
Remove `Services` of type `NodePort`.

---

### 2005 - Container images must come from trusted repositories.

#### Description
This rule follows the requirements from Kyverno policy [Allowed Image Repositories](https://release-1-12-0.kyverno.io/policies/other/allowed-image-repos/allowed-image-repos/).

#### Fix
Maintain an allowed list of image repositories and only use images for `Pods` from the allowed repositories.

---

### 2006 - Limit the use of wildcards in RBAC resources.

#### Description
This rule follows the requirements from Kyverno policy [Restrict Wildcards in Resources](https://release-1-12-0.kyverno.io/policies/other/restrict-wildcard-resources/restrict-wildcard-resources/).

#### Fix
Remove the use of wildcards `*` in `RBAC` resources.

---

### 2007 - Limit the use of wildcards in RBAC verbs.

#### Description
This rule follows the requirements from Kyverno policy [Restrict Wildcard in Verbs](https://release-1-12-0.kyverno.io/policies/other/restrict-wildcard-verbs/restrict-wildcard-verbs/).

#### Fix
Remove the use of wildcards `*` in `RBAC` verbs.

---

### 2008 - Pods must not be allowed to mount host directories.

#### Description
This rule follows the requirements from Kyverno pod security policy [Disallow hostPath](https://release-1-12-0.kyverno.io/policies/pod-security/baseline/disallow-host-path/disallow-host-path/).

#### Fix
Remove `Volumes` of type `hostPath` in `Pod` spec. 
