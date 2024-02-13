// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	option "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

const (
	IDNodeFiles = "node-files"
	IDPodFiles  = "pod-files"
)

type RuleOption interface {
	sharedv1r11.Options242406 | Options242414 | Options242415 | sharedv1r11.Options245543 | sharedv1r11.Options254800 | option.FileOwnerOptions
}
