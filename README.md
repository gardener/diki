# Diki
[![REUSE status](https://api.reuse.software/badge/github.com/gardener/diki)](https://api.reuse.software/info/github.com/gardener/diki)

[![gardener compliance checker](https://badgen.net/badge/gardener/compliance-checker/009f76)](https://github.com/gardener)
[![status alpha](https://badgen.net/badge/status/alpha/d8624d)](https://badgen.net/badge/status/alpha/d8624d)
[![license apache 2.0](https://badgen.net/badge/license/apache-2.0/8ab803)](https://opensource.org/licenses/Apache-2.0)


Diki a "compliance checker" or sorts, a detective control framework with pluggable rule sets. It's part of the [Gardener](https://github.com/gardener) family, but can be used also on other Kubernetes distros or even on non-Kubernetes environments, e.g. to check compliance of your hyperscaler accounts.

Diki is the Greek word for "trial". You can also memorise it as "Detective Investigation of Key Imperatives" or as GNU-style recursive acronym "Diki Investigates Key Imperatives". It's colloquially known as "Don't I Know It", which is a nice fit as well for what it does.

**Important Note:** This repository is in alpha stage. The API can change without any backwards compatibility.

## Getting Started

#### Installation

If you install via GitHub releases, you need to put the diki binary on your path.

A sample install snippet for macOS can look like this:
```bash
# Example for macOS

# set operating system and architecture
os=darwin # choose between darwin, linux, windows
arch=amd64 # choose between amd64, arm64

# Get latest version. Alternatively set your desired version
version=$(curl -Ls -H 'Accept: application/json' https://github.com/gardener/diki/releases/latest | jq -r '.tag_name')

# Download diki
curl -LO "https://github.com/gardener/diki/releases/download/${version}/diki-${os}-${arch}"

# Make the diki binary executable
chmod +x "./diki-${os}-${arch}"

# Move the binary in to your PATH
sudo mv "./diki-${os}-${arch}" /usr/local/bin/diki
```

#### Run

Most of Diki's `run` configurations are provided through its [config file](./example/config/). Options depend on the different providers and rulesets. Here are a couple of commands to get you started:

- Run all known rulesets for all known providers
```bash
diki run --config=config.yaml --all
```

- Run all known rulesets for all known providers and create a summary json report file
```bash
diki run --config=config.yaml --all --output=./report.json
```

- Run a specific ruleset for a known provider
```bash
diki run --config=config.yaml --provider=gardener --ruleset-id=disa-kubernetes-stig --ruleset-version=v1r11
```

- Run a specific rule defined in a ruleset for a known provider
```bash
diki run --config=config.yaml --provider=gardener --ruleset-id=disa-kubernetes-stig --ruleset-version=v1r11 --rule-id=242414
```

#### Report

Diki can generate a human readable report from the output files of a `diki run` execution. Merged reports can be produced by setting the `distinct-by` flag. The value of this flag is a list of `key=value` pairs where the keys are the IDs of the providers we want to include in the merged report and the values are the unique metadata fields to be used as distinction values between different provider runs.

- Generate an html report
```bash
diki report generate --output=report.hmtl output.json
```

- Generate merged html report
```bash
diki report generate --distinct-by=gardener=id --output=report.hmtl output1.json output2.json
```

#### Difference

Diki can generate a json containing the difference between 2 output files of `diki run` executions. This can help to identify improvements (or regressions).

- Generate json difference between 2 reports
```bash
diki report diff --old=output1.json --new=output2.json --output=difference.json
```

#### Unit Tests

You can manually run the tests via `make test`.

## Contributing

Contributions are very welcome. To learn more, see the [contributor guide](https://gardener.cloud/docs/contribute).

## Credits

A special thank you to @vlerenc, @AleksandarSavchev and @dimityrmirchev who made significant contributions to the project before it was made available to the public.
