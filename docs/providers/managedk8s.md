# Managed Kubernetes

## Provider

The `Managed Kubernetes` provider is capable of accessing a managed Kubernetes environment and running
`rulesets` against it.

## Rulesets

The `Managed Kubernetes` provider implements the following `rulesets`:

- [DISA Kubernetes Security Technical Implementation Guide](../rulesets/disa-k8s-stig/ruleset.md)
  - v2r4
  - v2r3

- [Security Hardened Kubernetes Cluster](../rulesets/security-hardened-k8s/ruleset.md)
  - v0.1.0

### Configuration

See an [example Diki configuration](../../example/config/managedk8s.yaml) for this provider.

#### Kubeconfig

The `Managed Kubernetes` provider requires a valid `kubeconfig` file to connect to the managed Kubernetes cluster.
The provider is supporting three ways to provide the `kubeconfig` file:

- Directly providing the path to the `kubeconfig` file in the provider configuration.
- Using the `KUBECONFIG` environment variable to point to the `kubeconfig` file.
- Using a mounted ServiceAccount token in a Kubernetes Pod.
