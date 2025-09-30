// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

type RuleOption interface {
	sharedrules.Options242390 |
		Options242400 |
		option.Options242414 |
		option.Options242415 |
		option.Options242442 |
		Options242451 |
		Options242466 |
		Options242467 |
		sharedrules.Options245543 |
		sharedrules.Options254800 |
		option.FileOwnerOptions
}
