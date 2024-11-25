# Security Hardened Kubernetes Cluster Guide

## Introduction

The Security Hardened Kubernetes Cluster Guide is created as an extension to the [DISA Kubernetes Security Technical Implementation Guide](../disa-k8s-stig/ruleset.md).
It aims to additionally increase the security posture of a Kubernetes cluster.
The ruleset is inspired and follows some of the policies from [Kyverno](https://github.com/kyverno/policies/tree/release-1.12).

## Rules

### 2000 - Ingress and egress traffic must be restricted by default.

#### Description
This rule follows the requirements from Kyverno best practices policy [Add Network Policy](https://github.com/kyverno/policies/tree/release-1.12/best-practices/add-network-policy/add-network-policy.yaml).

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
This rule follows the requirements from Kyverno pod security policy [Disallow Privilege Escalation](https://github.com/kyverno/policies/tree/release-1.12/pod-security/restricted/disallow-privilege-escalation/disallow-privilege-escalation.yaml).

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
This rule follows the requirements from Kyverno policy [Restrict StorageClass](https://github.com/kyverno/policies/tree/release-1.12/other/restrict-storageclass/restrict-storageclass.yaml).

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
This rule follows the requirements from Kyverno pod security policy [Restrict Volume Type](https://github.com/kyverno/policies/tree/release-1.12/pod-security/restricted/restrict-volume-types/restrict-volume-types.yaml).

#### Fix
Restrict `Pod` volume types to `configMap`, `csi`, `downwardAPI`, `emptyDir`, `ephemeral`, `persistentVolumeClaim`, `projected` and `secret`.

---

### 2004 - Limit the Services of type NodePort.

#### Description
This rule follows the requirements from Kyverno best practices policy [Disallow NodePort](https://github.com/kyverno/policies/tree/release-1.12/best-practices/restrict-node-port/restrict-node-port.yaml).

#### Fix
Remove `Services` of type `NodePort`.

---

### 2005 - Container images must come from trusted repositories.

#### Description
This rule follows the requirements from Kyverno policy [Allowed Image Repositories](https://github.com/kyverno/policies/tree/release-1.12/other/allowed-image-repos/allowed-image-repos.yaml).

#### Fix
Maintain an allowed list of image repositories and only use images for `Pods` from the allowed repositories.

---

### 2006 - Limit the use of wildcards in RBAC resources.

#### Description
This rule follows the requirements from Kyverno policy [Restrict Wildcards in Resources](https://github.com/kyverno/policies/tree/release-1.12/other/restrict-wildcard-resources/restrict-wildcard-resources.yaml).

#### Fix
Remove the use of wildcards `*` in `RBAC` resources.

---

### 2007 - Limit the use of wildcards in RBAC verbs.

#### Description
This rule follows the requirements from Kyverno policy [Restrict Wildcard in Verbs](https://github.com/kyverno/policies/tree/release-1.12/other/restrict-wildcard-verbs/restrict-wildcard-verbs.yaml).

#### Fix
Remove the use of wildcards `*` in `RBAC` verbs.

---

### 2008 - Pods must not mount host directories.

#### Description
This rule follows the requirements from Kyverno pod security policy [Disallow hostPath](https://github.com/kyverno/policies/tree/release-1.12/pod-security/baseline/disallow-host-path/disallow-host-path.yaml).

#### Fix
Remove `Volumes` of type `hostPath` in `Pod` spec. 
