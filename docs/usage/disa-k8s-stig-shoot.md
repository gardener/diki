---
description: How can I check whether my shoot cluster fulfills the DISA STIGs security requirements?
---

## Run DISA K8s STIGs Ruleset Against a Gardener Shoot Cluster

### Introduction

This part shows how to run the DISA K8s STIGs ruleset against a Gardener shoot cluster. 

The guide features two providers - `managedk8s` and `garden`, both of which implement rules from the DISA K8s STIG ruleset, as well as rules provided by the Gardener organization.

The `managedk8s` provider assumes that the user running the ruleset does not have access to the environment (the seed in this particular case), in which the control plane components reside.

The `garden` provider is used for accessing the`Garden` cluster, in which the `Shoot` resource can be found.

In order to run the ruleset for both providers, it is required to configure them with their required parameters, as specified in the following sections.

### Prerequisites

Make sure you have [diki installed](../../README.md#Installation) and have a running Gardener shoot cluster.

We will be using the sample [DISA K8s STIG for Shoots configuration file](../../example/guides/disa-k8s-stig-shoot.yaml) for this run.

#### Configuration for the `managedk8s` provider

For the `managedk8s` provider you will need to set the `provider.args.kubeconfigPath` field pointing to a shoot admin kubeconfig.

In case you need instructions on how to generate such a kubeconfig, please read [Accessing Shoot Clusters](https://github.com/gardener/gardener/blob/master/docs/usage/shoot/shoot_access.md).

Additional metadata such as the shoot's name can also be included in the `provider.metadata` section. The metadata section can be used to add additional context to different diki runs.

The provided configuration contains the recommended rule options for running the `managedk8s` provider ruleset against a shoot cluster, but you can modify rule options parameters according to requirements. All available options can be found in the [managedk8s example configuration](../../example/config/managedk8s.yaml).

#### Configuration for the `garden` provider

For the `garden` provider you will need to set the `provider.args.kubeconfigPath` field pointing to the garden cluster kubeconfig.

Additionally, the `provider.rulesets.args.projectNamespace` field should be set to the namespace in which the shoot cluster is deployed.

The `provider.rulesets.args.shootName` field should be set to the name of the shoot cluster.

Additional metadata can be included in the `provider.metadata` section as well. The metadata section can be used to add additional context to different diki runs.

#### Running the DISA K8s STIGs Ruleset

To run diki against a Gardener shoot cluster, run the following command:

```bash
diki run \
    --config=./example/guides/disa-k8s-stig-shoot.yaml \
    --all \
    --output=disa-k8s-stigs-report.json
```

#### Generating a Report

We can use the file generated in the previous step to create an html report by using the following command:

```bash
diki report generate \
    --output=disa-k8s-stigs-report.html \
    disa-k8s-stigs-report.json
```
