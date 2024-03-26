## Run Partial DISA K8s STIGs ruleset against a Gardener shoot cluster

### Introduction

This part shows how to run the DISA K8s STIGs ruleset against a Gardener shoot cluster. The `managedk8s` provider is used which does not check control plane components.

### Prerequisites

Make sure you have diki installed ([diki installation instructions](../../README.md#Installation)) and have a running Gardener shoot cluster.

### Configuration

We will be using the sample [partial-disa-k8s-stig-shoot configuration file](../../example/guides/partial-disa-k8s-stig-shoot.yaml) for this run. You will need to set the `provider.args.kubeconfigPath` field pointing to a shoot admin kubeconfig. In case you need instructions on how to generate such kubeconfig, please read the [shoot access guide](https://github.com/gardener/gardener/blob/master/docs/usage/shoot_access.md). Additional metadata such as the shoot's name can also be included in the `provider.metadata` section. The metadata section can be used to add addtional context to different diki runs.

The provided configuration contains the recommended rule options for running the `managedk8s` provider ruleset against a shoot cluster, but one can modify rule options parameters according to requirements. All available options can be found in the [managedk8s example configuration](../../example/config/managedk8s.yaml).

### Run DISA K8s STIGs ruleset

To run diki against a Gardener shoot cluster run the following command:
```bash
diki run \
    --config=./example/guides/managedshoot.yaml \
    --provider=managedk8s \
    --ruleset-id=disa-kubernetes-stig \
    --ruleset-version=v1r11 \
    --output=disa-k8s-stigs-report.json
```

### Generate a report

We can use the file generated in the previous step to create an html report using the following command:
```bash
diki report generate \
    --output=disa-k8s-stigs-report.json \
    disa-k8s-stigs-report.html
```
