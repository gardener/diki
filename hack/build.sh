#!/bin/bash

# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

platform="${1:-"linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64"}"
root_dir="$(readlink -f $(dirname ${0})/..)"
bin_path="${root_dir}/bin"

if [[ -z "${LD_FLAGS}" ]]; then
  LD_FLAGS=$("$root_dir"/hack/get-build-ld-flags.sh)
fi

for p in $platform
do
    out_file=${bin_path}/diki-${p}
    echo "building for ${t}: ${out_file}"
    os=$(echo "${p}" | cut -d "-" -f 1)
    arch=$(echo "${p}" | cut -d "-" -f 2)
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch GO111MODULE=on go build \
            -ldflags "${LD_FLAGS}" \
            -o "${out_file}" "${root_dir}"/cmd/diki/main.go
done
