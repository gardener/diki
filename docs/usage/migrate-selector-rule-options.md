---
description: How can I migrate my current selector rule options to the new labelSelector options?
---

## Migrate rule options to the new labelSelector options

With `v0.20.0` the `matchLabels` selectors for rule options are deprecated in favor of Kubernetes native `labelSelector`s.
The new selectors support both `matchExpressions` and `matchLabels`:
``` yaml
labelSelector:
  matchExpressions:
    - key: foo
      operator: In
      values:
      - bar
      - baz
      - qux
  matchLabels:
    foo: bar
```

There are also breaking changes where the options structure is being unified between selector rule options.

This guide will show you how to migrate to the new `labelSelector`s for rule options.
For specific rule options please check the [example config files](../../example/config)

### Rules where only `labelSelector` is added

Affected rule options:
- Security Hardened Kubernetes Cluster
  - 2000
  - 2001
  - 2002
  - 2003
  - 2004
  - 2006
  - 2007
  - 2008
- DISA K8s STIG
  - 242383

Old rule option:
``` yaml
- ruleID: "XXXX"
  args:
    acceptedPods:
    - matchLabels:
        foo: bar
      namespaceMatchLabels:
        foo: bar
```

New rule option:
``` yaml
- ruleID: "XXXX"
  args:
    acceptedPods:
    - labelSelector:
        matchLabels:
          foo: bar
      namespaceLabelSelector:
        matchLabels:
          foo: bar
```

### Rules which used `podMatchLabels` field

Affected rule options:
- DISA K8s STIG
  - 242414
  - 242415
  - 242417

Old rule option:
``` yaml
- ruleID: "XXXX"
  args:
    acceptedPods:
    - podMatchLabels:
        foo: bar
      namespaceMatchLabels:
        foo: bar
```

New rule option:
``` yaml
- ruleID: "XXXX"
  args:
    acceptedPods:
    - labelSelector:
        matchLabels:
          foo: bar
      namespaceLabelSelector:
        matchLabels:
          foo: bar
```

### Kube-proxy rules
Affected rule options:
- DISA K8s STIG
  - 242400
  - 242442
  - 242447
  - 242448
  - 242451
  - 242466
  - 242467

Old rule option:
``` yaml
- ruleID: "XXXX"
  args:
    kubeProxyDisabled: true
    kubeProxyMatchLabels:
      foo: bar
```

New rule option:
``` yaml
- ruleID: "XXXX"
  args:
    kubeProxy:
      disabled: true
      labelSelector:
        matchLabels:
          foo: bar
```

For rules `242447` & `242448` the `kube-proxy` options are directly composed
``` yaml
    - ruleID: "242447"
      args:
        labelSelector:
          matchLabels:
            foo: bar
```
