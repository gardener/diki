# Security Hardened Shoot Cluster Guide

## Introduction

The Security Hardened Shoot Cluster Guide is created by the Gardener team. It contains rules that check `Shoot` resources. The ruleset is inspired and follows some of the requirements from the [DISA Kubernetes Security Technical Implementation Guide](../disa-k8s-stig/ruleset.md).

## Rules

### 1000 - Shoot clusters should enable required extensions.

#### Description
Shoot clusters should enable required extensions. This rule can be configured as per organisation's requirements in order to check if required extensions are enabled for the shoot cluster.

#### Fix
Add the required extensions to the `spec.extensions` field.
``` yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
spec:
  extensions:
    - type: required-extension
```
---

### 2000 - Shoot clusters must have anonymous authentication disabled for the Kubernetes API server.

#### Description
Shoot clusters must have anonymous authentication disabled for the Kubernetes API server. This rule follows the requirements from DISA K8s STIG rule [242390](https://www.stigviewer.com/stig/kubernetes/2024-06-10/finding/V-242390).

#### Fix
Do not set `spec.kubernetes.enableAnonymousAuthentication` field as it defaults to `false` or set it explicitly to `false`.
``` yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
spec:
  kubernetes:
    enableAnonymousAuthentication: false
```
---

### 2001 - Shoot clusters must disable ssh access to worker nodes.

#### Description
Shoot clusters must disable worker nodes ssh access in order to lower possible attack vectors. This rule follows the requirements from DISA K8s STIG rules [242393](https://www.stigviewer.com/stig/kubernetes/2024-06-10/finding/V-242393) and [242394](https://www.stigviewer.com/stig/kubernetes/2024-06-10/finding/V-242394).

#### Fix
Set the `spec.provider.workersSettings.sshAccess.enabled` field to `false`.
``` yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
spec:
  provider:
    workersSettings:
      sshAccess:
        enabled: false
```
---

### 2002 - Shoot clusters must not have Alpha APIs enabled for any Kubernetes component.

#### Description
Shoot clusters must not have the allAlpha feature gate enabled for any of their components. This rule follows the requirements from DISA K8s STIG rule [242400](https://www.stigviewer.com/stig/kubernetes/2024-06-10/finding/V-242400).

#### Fix
Do not set `spec.kubernetes.{kubeAPIServer,kubeControllerManager,kubeScheduler,kubeProxy,kubelet}.featureGate.allAlpha` fields as they default to `false` or set them explicitly to `false`
``` yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
spec:
  kubernetes:
    kubeAPIServer:
      featureGate:
        allAlpha: false
    kubeControllerManager:
      featureGate:
        allAlpha: false
    kubeScheduler:
      featureGate:
        allAlpha: false
    kubeProxy:
      featureGate:
        allAlpha: false
    kubelet:
      featureGate:
        allAlpha: false
```
---

### 2003 - Shoot clusters must enable kernel protection for Kubelet.

#### Description
Shoot clusters must enable kernel protection for Kubelet. This rule follows the requirements from DISA K8s STIG rule [242434](https://www.stigviewer.com/stig/kubernetes/2024-06-10/finding/V-242434).

#### Fix
Set the `spec.kubernetes.kubelet.protectKernelDefaults` field to `true`. For `Shoot`s with `Kubernetes` version >= `v1.26` it defaults to `true`.
``` yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
spec:
  kubernetes:
    kubelet:
      protectKernelDefaults: true
```
---

### 2004 - Shoot clusters must have ValidatingAdmissionWebhook admission plugin enabled.

#### Description
Shoot clusters must have ValidatingAdmissionWebhook admission plugin enabled. This rule follows the requirements from DISA K8s STIG rule [242436](https://www.stigviewer.com/stig/kubernetes/2024-06-10/finding/V-242436).

#### Fix
Remove the `ValidatingAdmissionWebhook` admission plugin from `spec.kubernetes.kubeAPIServer.admissionPlugins` field as it defaults to enabled.

---

### 2005 - Shoot clusters must not disable timeouts for Kubelet.

#### Description
Shoot clusters must not disable timeouts for Kubelet. The timeout must be between 5m and 4h. It is recommended for the timeout to be 5m. This rule follows the requirements from DISA K8s STIG rule [245541](https://www.stigviewer.com/stig/kubernetes/2024-06-10/finding/V-245541).

#### Fix
Set the `spec.kubernetes.kubelet.streamingConnectionIdleTimeout` field to an allowed value (`5m` <= `value` <= `4h`). For `Shoot`s with `Kubernetes` version >= `v1.26` it defaults to the recommended value `5m`.
``` yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
spec:
  kubernetes:
    kubelet:
      streamingConnectionIdleTimeout: 5m
```
---

### 2006 - Shoot clusters must have static token kubeconfig disabled.

#### Description
Shoot clusters must have static token kubeconfig disabled. This rule follows the requirements from DISA K8s STIG rule [245543](https://www.stigviewer.com/stig/kubernetes/2024-06-10/finding/V-245543).

#### Fix
Set the `spec.kubernetes.kubelet.enableStaticTokenKubeconfig` to `false`. For `Shoot`s with `Kubernetes` version >= `v1.27` it is locked to `false`, for version = `v1.26` it defaults to `false`.
``` yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
spec:
  kubernetes:
    enableStaticTokenKubeconfig: false
```
---

### 2007 - Shoot clusters must have a PodSecurity admission plugin configured.

#### Description
Shoot clusters must have a PodSecurity admission plugin configured. It is recommended to set default pod security standards to `baseline` or `restricted` level. This rule follows the requirements from DISA K8s STIG rule [242434](https://www.stigviewer.com/stig/kubernetes/2024-06-10/finding/V-254800).

#### Fix
Add `PodSecurity` admission plugin into `spec.kubernetes.kubeAPIServer.admissionPlugins` field with default standards set to `baseline` or `restricted`.
``` yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
spec:
  kubernetes:
    kubeAPIServer:
      admissionPlugins:
        - name: PodSecurity
          config:
            apiVersion: pod-security.admission.config.k8s.io/v1
            kind: PodSecurityConfiguration
            defaults:
              enforce: baseline
              audit: baseline
              warn: baseline
          disabled: false
```
