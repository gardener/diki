// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"github.com/gardener/diki/pkg/config/merge"
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
			ProviderID: "virtualgarden",
			RulesetID:  RulesetID,
			Version:    version,
			RuleID:     ruleID,
		}
	}

	merge.RegisterMergeFunc[sharedrules.Options242383](r, key(sharedrules.ID242383))
	merge.RegisterMergeFunc[sharedrules.Options242390](r, key(sharedrules.ID242390))
	merge.RegisterMergeFunc[sharedrules.Options242393](r, key(sharedrules.ID242393))
	merge.RegisterMergeFunc[sharedrules.Options242394](r, key(sharedrules.ID242394))
	merge.RegisterMergeFunc[sharedrules.Options242396](r, key(sharedrules.ID242396))
	merge.RegisterMergeFunc[sharedrules.Options242404](r, key(sharedrules.ID242404))
	merge.RegisterMergeFunc[sharedrules.Options242406](r, key(sharedrules.ID242406))
	merge.RegisterMergeFunc[sharedrules.Options242407](r, key(sharedrules.ID242407))
	merge.RegisterMergeFunc[disaoption.Options242414](r, key(sharedrules.ID242414))
	merge.RegisterMergeFunc[disaoption.Options242415](r, key(sharedrules.ID242415))
	merge.RegisterMergeFunc[sharedrules.Options242417](r, key(sharedrules.ID242417))
	merge.RegisterMergeFunc[disaoption.Options242442](r, key(sharedrules.ID242442))
	merge.RegisterMergeFunc[disaoption.FileOwnerOptions](r, key(sharedrules.ID242445))
	merge.RegisterMergeFunc[disaoption.FileOwnerOptions](r, key(sharedrules.ID242446))
	merge.RegisterMergeFunc[sharedrules.Options242448](r, key(sharedrules.ID242448))
	merge.RegisterMergeFunc[sharedrules.Options242449](r, key(sharedrules.ID242449))
	merge.RegisterMergeFunc[sharedrules.Options242450](r, key(sharedrules.ID242450))
	merge.RegisterMergeFunc[disaoption.FileOwnerOptions](r, key(sharedrules.ID242451))
	merge.RegisterMergeFunc[sharedrules.Options242452](r, key(sharedrules.ID242452))
	merge.RegisterMergeFunc[sharedrules.Options242453](r, key(sharedrules.ID242453))
	merge.RegisterMergeFunc[sharedrules.Options245543](r, key(sharedrules.ID245543))
	merge.RegisterMergeFunc[sharedrules.Options254800](r, key(sharedrules.ID254800))
}
