# Diki

[![gardener compliance checker](https://badgen.net/badge/gardener/compliance-checker/009f76)](https://github.com/gardener)
[![status alpha](https://badgen.net/badge/status/alpha/d8624d)](https://badgen.net/badge/status/alpha/d8624d)
[![license apache 2.0](https://badgen.net/badge/license/apache-2.0/8ab803)](https://opensource.org/licenses/Apache-2.0)


Diki a "compliance checker" or sorts, a detective control framework with pluggable rule sets. It's part of the [Gardener](https://github.com/gardener) family, but can be used also on other Kubernetes distros or even on non-Kubernetes environments, e.g. to check compliance of your hyperscaler accounts.

Diki is the Greek word for "trial". You can also memorise it as "Detective Investigation of Key Imperatives" or as GNU-style recursive acronym "Diki Investigates Key Imperatives". It's colloquially known as "Don't I Know It", which is a nice fit as well for what it does.

**Important Note:** This repository is in alpha stage. The API can change without any backwards compatibility.

## Getting Started

#### Installation

TODO

#### Run

Most of Diki's `run` configurations are provided through its [config file](./config.yaml). Options depend on the different providers and rulesets. Here are a couple of commands to get you started:

- Run all known rulesets for all known providers
```bash
diki run --config=config.yaml --all
```

- Run a specific ruleset for a known provider
```bash
diki run --config=config.yaml --provider=gardener --ruleset-id=disa-kubernetes-stig --ruleset-version=v1r8
```

- Run a specific rule defined in a ruleset for a known provider
```bash
diki run --config=config.yaml --provider=gardener --ruleset-id=disa-kubernetes-stig --ruleset-version=v1r8 --rule-id=242414
```

#### Report

Generate an html report
```bash
diki report output.json > report.hmtl
```

#### Unit Tests

You can manually run the tests via `make test`.

## Contributing

Contributions are very welcome. To learn more, see the [contributor guide](https://gardener.cloud/docs/contribute).
