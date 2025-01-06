# Managed Kubernetes

## Provider

The `Managed Kubernetes` provider is capable of accessing a managed Kubernetes environment and running `rulesets` against it.

## Rulesets

The `Managed Kubernetes` provider implements the following `rulesets`:
- [DISA Kubernetes Security Technical Implementation Guide](../rulesets/disa-k8s-stig/ruleset.md)
    - v2r2
    - v2r1
    
- [Security Hardened Kubernetes Cluster](../rulesets/security-hardened-k8s/ruleset.md)
    - v0.1.0

### Configuration

See an [example Diki configuration](../../example/config/managedk8s.yaml) for this provider.
