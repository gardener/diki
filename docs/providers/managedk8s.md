# Managed Kubernetes

## Provider

The `Managed Kubernetes` provider is capable of accessing a `GKE cluster` environment and running `rulesets` against it.

## Rulesets

The `Gardener` provider implements the following `rulesets`:
- [DISA Kubernetes Security Technical Implementation Guide](../rulesets/disa-k8s-stig.md)
    - v1r11

### Configuration

See an [example Diki configuration](../../example/config/managedk8s.yaml) for this provider.
