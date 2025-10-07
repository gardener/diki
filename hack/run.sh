#!/bin/bash

# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

rule_id=""
provider="gardener"
ruleset_id="disa-kubernetes-stig"
ruleset_version="v2r4"
run_all="false"


function usage {
    cat <<EOM
Usage:
run [options]

This command runs diki with a specified config file.

  options:
    -h, --help        Display this help and exit.
    --config          Path to diki configuration file.
    --all             If set diki runs all rulesets specified in the config file.
                      Also ignore all flags except --config.
    --rule-id         ID of single rule that will be ran. If not set all rules of the
                      specified ruleset are executed.
    --provider        Ruleset provider. Defaults to "gardener".
    --ruleset-id      ID of ruleset that will be ran. Defaults to "disa-kubernetes-stig".
    --ruleset-version Version of ruleset that will be ran. Defaults to "v2r4".
    
  environment variables:
    IMAGEVECTOR_OVERWRITE Overwrites diki/imagesvector/images.yaml file with specified file path.
    LD_FLAGS              ldflags of go run diki command. Default ldflags will be generated if it is not set.
EOM
    exit 0
}

while :; do
  case $1 in
    -h|--help)
      usage
      ;;
    --)
      shift
      break
      ;;
    --all)
      run_all="true"
      ;;
    --config=*|--rule-id=*|--provider=*|--ruleset-id=*|--ruleset-version=*)
      var="${1%%=*}"
      var="${var#*--}"
      var="${var//-/_}"
      declare "${var}"="${1#*=}"
      ;;
    --config|--rule-id|--provider|--ruleset-id|--ruleset-version)
      var="${1#*--}"
      var="${var//-/_}"
      declare "${var}"="${2}"
      shift
      ;;
    --*)
      var="${1%%=*}"
      echo "Error: ${var} flag is not recognized!" >&2
      usage
      ;;
    *)
      break
  esac
  shift
done

if [ -z "${config}" ]; then
  echo "Error: --config flag not set!" >&2
  usage
fi

if [ -z "${LD_FLAGS}" ]; then
  EFFECTIVE_VERSION="$(cat "$(dirname "$0")/../VERSION")"-"$(git rev-parse HEAD)"
  LD_FLAGS=$(EFFECTIVE_VERSION=${EFFECTIVE_VERSION} "$(dirname "$0")"/get-build-ld-flags.sh)
fi

if [ "${run_all}" = "true" ]; then
  go run -ldflags "${LD_FLAGS}" \
  "$(dirname "$0")"/../cmd/diki run \
  --config="${config}" \
  --all

  exit 0
fi

go run -ldflags "${LD_FLAGS}" \
"$(dirname "$0")"/../cmd/diki run \
--config="${config}" \
--rule-id="${rule_id}" \
--provider="${provider}" \
--ruleset-id="${ruleset_id}" \
--ruleset-version="${ruleset_version}"
