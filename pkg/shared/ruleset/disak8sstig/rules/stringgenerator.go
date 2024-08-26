// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import "github.com/gardener/diki/pkg/internal/stringgen"

var (
	// Generator is a not secure random Generator. Exposed for testing purposes.
	Generator stringgen.StringGenerator = stringgen.Default()
)
