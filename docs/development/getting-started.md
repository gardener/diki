## Getting Started

### Core Diki packages

- the [provider package](../../pkg/provider/) defines a `provider`. This can be anything that you can run `rulesets` and `rules` against, i.e. a kubernetes cluster, cloud provider account, etc.
- the [ruleset package](../../pkg/ruleset/) defines a `ruleset`. A `ruleset` is a versioned combination of `rules`.
- the [rule package](../../pkg/rule/) defines a `rule`. A `rule` is a concrete implementation of a requirement.
- the [report package](../../pkg/report/) defines a `report`. A `report` is the output of a `diki` run.

See the [provider specific documentation](../providers/).

## Running diki Locally

This part will walk you through the process of running Diki against a local shoot cluster for development purposes. This guide uses the Gardener's local development setup.
If you encounter difficulties, please open an issue so that we can make this process easier.

### Prerequisites

Make sure that you have a running local Gardener setup with a created shoot cluster. The steps to complete this can be found [here](https://github.com/gardener/gardener/blob/master/docs/deployment/getting_started_locally.md).

### Diki configuration

You can use the [example gardener configuration](../../example/config/gardener.yaml) for this run. You will need to modify the `provider.args` field with correct kubeconfigs and shoot name/ namespace. You can can find a guide on how to get the shoot's kubeconfig [here](https://github.com/gardener/gardener/blob/master/docs/deployment/getting_started_locally.md).

### Diki run

To run Diki you can use the [run script](../../hack/run.sh). It will use default ldflags flags or you can configure them by setting the `LD_FLAGS` env var. You will need to set the `IMAGEVECTOR_OVERWRITE` env var to overwrite the [images.yaml](../../imagevector/images.yaml) file to a file that specifies the version of the `diki-ops` image or change it's repository.

After creating the overwrite images file you can run diki as follows:
```bash
IMAGEVECTOR_OVERWRITE=/path/to/images/file ./hack/run.sh --config=/path/to/config/file
```

For more information about the script you can use it's help command:
```bash
./hack/run.sh --help
```
