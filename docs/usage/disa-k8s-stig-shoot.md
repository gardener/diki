---
description: How can I check whether my shoot cluster fulfills the DISA STIG security requirements?
---

## Show DISA K8s STIG Compliance for a Gardener Shoot Cluster

### Introduction

This part covers the topic of showing compliance with the DISA K8s STIG for a Gardener shoot cluster. The guide features two providers - `managedk8s` and `garden`, both of which implement rules from the DISA K8s STIG ruleset.

The `managedk8s` provider assumes that the user running the ruleset does not have access to the environment (the seed in this particular case), in which the control plane components reside.

The `garden` provider is used for accessing the`Garden` cluster, in which the `Shoot` resource can be found.

> [!IMPORTANT]
> Since the two providers that we are going to use in this guide do not leverage access to the Shoot cluster controlplane,
> they only implement checks that concern configurations that cluster owners can change/modify by themselves.
> Compliance for configurations that cannot be influenced by cluster owners shall be ensured by the team that operates the concrete Gardener installation.

### Prerequisites

Make sure you have [diki installed](../../README.md#Installation) and have a running Gardener shoot cluster.

We will be using the sample [DISA K8s STIG for Shoots configuration file](../../example/guides/disa-k8s-stig-shoot.yaml) for this run.

### Configuration

#### Configure the `managedk8s` provider

Set the following arguments:
- `providers[id=="managedk8s"].args.kubeconfigPath` pointing to a shoot admin kubeconfig.
- (optional) `providers[id=="managedk8s"].metadata.shootName` should be set to the name of the shoot cluster. The `metadata` field contains custom metadata from the user that will be present in the generated report.

``` yaml
- id: managedk8s
  name: "Managed Kubernetes"
  metadata:
    # foo: bar
    # shootName: <shoot-name>
  args:
    kubeconfigPath: <shoot-kubeconfig-path>  # path to shoot admin kubeconfig
```

In case you need instructions on how to generate such a kubeconfig, please read [Accessing Shoot Clusters](https://github.com/gardener/gardener/blob/master/docs/usage/shoot/shoot_access.md).

#### Configure the `garden` provider

Set the following arguments:
- `providers[id=="garden"].args.kubeconfigPath` pointing to the Garden cluster kubeconfig.
- `providers[id=="garden"].rulesets.args.projectNamespace` should be set to the namespace in which the shoot cluster is created.
- `providers[id=="garden"].rulesets.args.shootName` should be set to the name of the shoot cluster.

``` yaml
- id: garden
  name: "Garden"
  metadata:
  #  foo: bar
  args:
    kubeconfigPath: <garden-kubeconfig-path>  # path to garden cluster kubeconfig
  rulesets:
  - id: security-hardened-shoot-cluster
    name: Security Hardened Shoot Cluster
    version: v0.2.1
    args:
      projectNamespace: garden-<project-name> # name of project namespace containing the shoot resource to be tested
      shootName: <shoot-name>                 # name of shoot resource to be tested
```

#### Additional configurations

Additional metadata such as the shoot's name can also be included in the `providers[id=="managedk8s|garden"].metadata` section. The metadata section can be used to add additional context to different diki runs.

The provided configuration contain the recommended rule options for running the both providers, but you can modify rule options parameters according to requirements. All available options can be found in:
- [managedk8s example configuration](../../example/config/managedk8s.yaml).
- [garden example configuration](../../example/config/garden.yaml).

### Running the DISA K8s STIGs Ruleset

To run diki against a Gardener shoot cluster, run the following command:

```bash
diki run \
    --config=./example/guides/disa-k8s-stig-shoot.yaml \
    --all \
    --output=disa-k8s-stigs-report.json
```

### Generating a Report

We can use the file generated in the previous step to create an html report by using the following command:

```bash
diki report generate \
    --output=disa-k8s-stigs-report.html \
    disa-k8s-stigs-report.json
```
