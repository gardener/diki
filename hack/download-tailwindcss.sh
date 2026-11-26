#!/bin/bash

# SPDX-FileCopyrightText: Contributors to the Gardener project
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

out_file="${1:?usage: download-tailwindcss.sh <out-file> <version> <platform>}"
version="${2:?usage: download-tailwindcss.sh <out-file> <version> <platform>}"

base_url="https://github.com/tailwindlabs/tailwindcss/releases/download/${version}"
platform=$(uname -s | tr '[:upper:]' '[:lower:]' | sed 's/darwin/macos/')-$(uname -m | sed 's/x86_64/x64/' | sed 's/aarch64/arm64/')

curl -Lf -o "${out_file}" "${base_url}/tailwindcss-${platform}"

checksum="$(curl -sLf "${base_url}/sha256sums.txt" | grep " tailwindcss-${platform}$" | cut -d ' ' -f 1)"
if [ -z "${checksum}" ]; then
  echo "Error: could not determine tailwindcss checksum for platform ${platform}"
  exit 1
fi

echo "${checksum}  ${out_file}" | sha256sum -c -

chmod +x "${out_file}"
