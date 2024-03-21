## Run Partial DISA k8s STIGs ruleset against a Gardener shoot cluster

### Introduction

This part shows how to run the DISA k8s STIGs ruleset against a Gardener shoot cluster when you do not access to a seed kubeconfig. The `managedk8s` provider is used which does not check `ControlPlane` components.

### Prerequisites

Make sure you have installed diki (how to install diki can be found [here](../../README.md#Installation)) and have a running Gardener shoot cluster.

### Configuration

We will be using the [guides partial-disa-k8s-stig-shoot configuration](../../example/guides/partial-disa-k8s-stig-shoot.yaml) for this run. You will need to modify the `provider.args` field with correct shoot admin kubeconfig. You can can find a guide on how to get the kubeconfig [here](https://github.com/gardener/gardener/blob/master/docs/usage/shoot_access.md).

The provided configuration contains the recommended rule options for running the `managedk8s` provider ruleset against a shoot cluster. For specific cluster the rule options can be changed in order for the report to show more accurate compliance. A full picture of all rule options can be found [here](../../example/config/managedk8s.yaml).

### Run diki

To run diki against a Gardener shoot cluster we can simply use the `run` command:
```bash
diki run --config=./example/guides/managedshoot.yaml --provider=managedk8s --ruleset-id=disa-kubernetes-stig --ruleset-version=v1r11
```

We can also select a single rule to be ran with the `--rule-id` flag:
```bash
diki run --config=./example/guides/managedshoot.yaml --provider=managedk8s --ruleset-id=disa-kubernetes-stig --ruleset-version=v1r11 --rule-id=242414
```

### Generate diki report

After running diki an output file is generated if the `output.path` configuration is set. In the example config it is set to `/tmp/output.json`. We can use this file to create a html diki report using the following command:
```bash
diki report generate --output=/tmp/output.html /tmp/output.json
```
