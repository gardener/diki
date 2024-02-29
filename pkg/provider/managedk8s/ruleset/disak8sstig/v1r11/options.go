// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

type RuleOption interface {
	sharedv1r11.Options242393 |
		sharedv1r11.Options242394 |
		sharedv1r11.Options242406 |
		sharedv1r11.Options242407 |
		Options242414 |
		Options242415 |
		sharedv1r11.Options242417 |
		sharedv1r11.Options242447 |
		sharedv1r11.Options242448 |
		sharedv1r11.Options242449 |
		sharedv1r11.Options242452 |
		sharedv1r11.Options242453 |
		Options242466 |
		option.FileOwnerOptions
}
