---
description: How can I check whether my shoot cluster fulfills the Security Hardened Kubernetes Cluster requirements?
---

## Show Security Hardened Kubernetes Compliance for a Gardener Shoot Cluster

### Introduction

This part covers the topic of showing compliance with the Security Hardened Kubernetes Cluster requirements for a Gardener shoot cluster. The guide features the `managedk8s` provider, which implements rules from the Security Hardened Kubernetes Cluster ruleset.

### Prerequisites

Make sure you have [diki installed](../../README.md#Installation) and have a running Gardener shoot cluster.

We will be using the sample [Security Hardened Kubernetes Guide for Shoots configuration file](../../example/guides/security-hardened-k8s-shoot.yaml) for this run.

In order to complete its compliance checking, Diki will require permissions to access certain Gardener resources.
[A compiled list of RBAC-style rules is provided](../../example/rbac/garden.yaml), which represents all required permissions for the ruleset run. You may use this list to create your own RBAC resources.

### Configuration

#### Configure the `managedk8s` provider

Set the following arguments:
- `providers[id=="managedk8s"].args.kubeconfigPath` pointing to a shoot admin kubeconfig.
- (optional) `providers[id=="managedk8s"].metadata.shootName` should be set to the name of the shoot cluster. The `metadata` field contains custom metadata from the user that will be present in the generated report.

``` yaml
- id: managedk8s
  name: "Managed Kubernetes"
  metadata: # custom user metadata
    # shootName: <shoot-name>
  args:
    kubeconfigPath: <shoot-kubeconfig-path>  # path to shoot admin kubeconfig
```

In case you need instructions on how to generate such a kubeconfig, please read [Accessing Shoot Clusters](https://github.com/gardener/gardener/blob/master/docs/usage/shoot/shoot_access.md).

#### Additional configurations

Additional metadata such as the shoot's name can also be included in the `providers[id=="managedk8s].metadata` section. The metadata section can be used to add additional context to different diki runs.

The provided configuration contains the recommended rule options for running the both providers, but you can modify rule options parameters according to requirements. All available options can be found in:
- [managedk8s example configuration](../../example/config/managedk8s.yaml).

### Running the DISA K8s STIGs Ruleset

To run diki against a Gardener shoot cluster, run the following command:

```bash
diki run \
    --config=./example/guides/security-hardened-k8s-shoot.yaml \
    --provider=managedk8s \
    --ruleset-id=security-hardened-k8s \
    --ruleset-version=v0.1.0 \
    --output=security-hardened-k8s-shoot-report.json
```

### Generating a Report

We can use the file generated in the previous step to create an html report by using the following command:

```bash
diki report generate \
    --output=security-hardened-k8s-shoot-report.html \
    security-hardened-k8s-shoot-report.json
```