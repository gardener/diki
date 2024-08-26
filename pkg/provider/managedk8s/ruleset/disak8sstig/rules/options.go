// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

type RuleOption interface {
	sharedrules.Options242383 |
		sharedrules.Options242393 |
		sharedrules.Options242394 |
		sharedrules.Options242396 |
		Options242400 |
		sharedrules.Options242404 |
		sharedrules.Options242406 |
		sharedrules.Options242407 |
		option.Options242414 |
		option.Options242415 |
		sharedrules.Options242417 |
		Options242442 |
		sharedrules.Options242447 |
		sharedrules.Options242448 |
		sharedrules.Options242449 |
		sharedrules.Options242450 |
		Options242451 |
		sharedrules.Options242452 |
		sharedrules.Options242453 |
		Options242466 |
		Options242467
}
