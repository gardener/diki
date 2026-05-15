// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"github.com/gardener/diki/pkg/config/merge"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/rules"
	disaoption "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

// RegisterMergeFuncs registers all rule option merge functions for the
// DISA Kubernetes STIG ruleset (gardener provider).
func RegisterMergeFuncs(r *merge.Registry) {
	for _, version := range SupportedVersions {
		registerMergeFuncs(r, version)
	}
}

func registerMergeFuncs(r *merge.Registry, version string) {
	key := func(ruleID string) merge.RegistryKey {
		return merge.RegistryKey{
			ProviderID: gardener.ProviderID,
			RulesetID:  RulesetID,
			Version:    version,
			RuleID:     ruleID,
		}
	}

	merge.RegisterMergeFunc[sharedrules.Options242390](r, key(sharedrules.ID242390))
	merge.RegisterMergeFunc[rules.Options242400](r, key(sharedrules.ID242400))
	merge.RegisterMergeFunc[disaoption.Options242414](r, key(sharedrules.ID242414))
	merge.RegisterMergeFunc[disaoption.Options242415](r, key(sharedrules.ID242415))
	merge.RegisterMergeFunc[disaoption.Options242442](r, key(sharedrules.ID242442))
	merge.RegisterMergeFunc[disaoption.FileOwnerOptions](r, key(sharedrules.ID242445))
	merge.RegisterMergeFunc[disaoption.FileOwnerOptions](r, key(sharedrules.ID242446))
	merge.RegisterMergeFunc[rules.Options242451](r, key(sharedrules.ID242451))
	merge.RegisterMergeFunc[rules.Options242466](r, key(sharedrules.ID242466))
	merge.RegisterMergeFunc[rules.Options242467](r, key(sharedrules.ID242467))
	merge.RegisterMergeFunc[sharedrules.Options245543](r, key(sharedrules.ID245543))
	merge.RegisterMergeFunc[sharedrules.Options254800](r, key(sharedrules.ID254800))
}
