#!/bin/bash

# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

old_version=${1}
old_version_uppercase=$(echo ${old_version} | tr 'a-z' 'A-Z')
new_version=${2}
new_version_uppercase=$(echo ${new_version} | tr 'a-z' 'A-Z')

cd "$(dirname "$0")"
disak8sstig_path="../pkg/provider/gardener/ruleset/disak8sstig"
old_version_dir="${disak8sstig_path}/${old_version}"
new_version_dir="${disak8sstig_path}/${new_version}"
old_ruleset_file="${disak8sstig_path}/${old_version}_ruleset.go"
new_ruleset_file="${disak8sstig_path}/${new_version}_ruleset.go"

if [ -d ${new_version_dir} ]; then
  echo "error: directory for ${new_version} already exists."
  exit 1
fi

if [ -f ${new_ruleset_file} ]; then
  echo "error: ruleset file for ${new_version} already exists."
  exit 1
fi

cp -r ${old_version_dir} ${new_version_dir}
cp ${old_ruleset_file} ${new_ruleset_file}

find ${new_version_dir} -name '*.go' -exec sed -i -e "s/${old_version}/${new_version}/g" -e "s/${old_version_uppercase}/${new_version_uppercase}/g" {} \;
sed -i -e "s/${old_version}/${new_version}/g" -e "s/${old_version_uppercase}/${new_version_uppercase}/g" ${new_ruleset_file}
find ${new_version_dir} -name '*.go' -exec bash -c 'mv "$0" "$(echo "$0" | sed s/'"${old_version}/${new_version}"'/)" 2>/dev/null' {} \;
