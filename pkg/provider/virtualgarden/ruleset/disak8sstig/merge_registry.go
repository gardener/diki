// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"github.com/gardener/diki/pkg/config/merge"
	"github.com/gardener/diki/pkg/provider/virtualgarden"
	disaoption "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

// RegisterMergeFuncs registers all rule option merge functions for the
// DISA Kubernetes STIG ruleset (virtualgarden provider).
func RegisterMergeFuncs(r *merge.Registry) {
	for _, version := range SupportedVersions {
		registerMergeFuncs(r, version)
	}
}

func registerMergeFuncs(r *merge.Registry, version string) {
	key := func(ruleID string) merge.RegistryKey {
		return merge.RegistryKey{
			ProviderID: virtualgarden.ProviderID,
			RulesetID:  RulesetID,
			Version:    version,
			RuleID:     ruleID,
		}
	}

	merge.RegisterMergeFunc[sharedrules.Options242390](r, key(sharedrules.ID242390))
	merge.RegisterMergeFunc[disaoption.Options242442](r, key(sharedrules.ID242442))
	merge.RegisterMergeFunc[disaoption.FileOwnerOptions](r, key(sharedrules.ID242445))
	merge.RegisterMergeFunc[disaoption.FileOwnerOptions](r, key(sharedrules.ID242446))
	merge.RegisterMergeFunc[disaoption.FileOwnerOptions](r, key(sharedrules.ID242451))
	merge.RegisterMergeFunc[sharedrules.Options245543](r, key(sharedrules.ID245543))
}
