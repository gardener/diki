// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package imagevector

import _ "embed"

// Images YAML contains the contents of the images.yaml file.
//
//go:embed images.yaml
var ImagesYAML string
