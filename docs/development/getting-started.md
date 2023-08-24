## Getting Started

### Core Diki packages

- the [provider package](../../pkg/provider/) defines a `provider`. This can be anything that you can run `rulesets` and `rules` against, i.e. a kubernetes cluster, cloud provider account, etc.
- the [ruleset package](../../pkg/ruleset/) defines a `ruleset`. A `ruleset` is a versioned combination of `rules`.
- the [rule package](../../pkg/rule/) defines a `rule`. A `rule` is a concrete implementation of a requirement.
- the [report package](../../pkg/report/) defines a `report`. A `report` is the output of a `diki` run.

See the [provider specific documentation](../providers/).
