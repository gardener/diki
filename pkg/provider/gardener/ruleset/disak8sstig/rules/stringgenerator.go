// SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package rules

import "github.com/gardener/diki/pkg/internal/stringgen"

var (
	// Generator is a not secure random Generator. Exposed for testing purposes.
	Generator stringgen.StringGenerator = stringgen.Default()
)
