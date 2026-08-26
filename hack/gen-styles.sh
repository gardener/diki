#!/bin/bash

# SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
#
# SPDX-License-Identifier: Apache-2.0

set -e

tailwindcss -c ./tailwind.config.js -i ./pkg/report/templates/html/input.css -o ./pkg/report/templates/html/output.css --minify

cat <<EOF > ./pkg/report/templates/html/_styles.tpl
{{define "_styles"}}
<style>
$(cat ./pkg/report/templates/html/output.css)
</style>
{{end}}
EOF
