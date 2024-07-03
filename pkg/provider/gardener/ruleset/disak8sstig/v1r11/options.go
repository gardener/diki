// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	option "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

type RuleOption interface {
	option.Options242414 |
		option.Options242415 |
		sharedv1r11.Options245543 |
		sharedv1r11.Options254800 |
		option.FileOwnerOptions |
		option.KubeProxyOptions
}
