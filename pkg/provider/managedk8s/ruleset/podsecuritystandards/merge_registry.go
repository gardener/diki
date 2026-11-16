// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package podsecuritystandards

import (
	"github.com/gardener/diki/pkg/config/merge"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/podsecuritystandards/rules"
)

// RegisterMergeFuncs registers all rule option merge functions for the
// Pod Security Standards ruleset (managedk8s provider).
func RegisterMergeFuncs(r *merge.Registry) {
	for _, version := range SupportedVersions {
		registerV01MergeFuncs(r, version)
	}
}

func registerV01MergeFuncs(r *merge.Registry, version string) {
	key := func(ruleID string) merge.RegistryKey {
		return merge.RegistryKey{
			ProviderID: "managedk8s",
			RulesetID:  RulesetID,
			Version:    version,
			RuleID:     ruleID,
		}
	}

	merge.RegisterMergeFunc[rules.OptionsPSSB001](r, key("PSS-B001"))
	merge.RegisterMergeFunc[rules.OptionsPSSB002](r, key("PSS-B002"))
	merge.RegisterMergeFunc[rules.OptionsPSSB003](r, key("PSS-B003"))
	merge.RegisterMergeFunc[rules.OptionsPSSB004](r, key("PSS-B004"))
	merge.RegisterMergeFunc[rules.OptionsPSSB005](r, key("PSS-B005"))
	merge.RegisterMergeFunc[rules.OptionsPSSB006](r, key("PSS-B006"))
	merge.RegisterMergeFunc[rules.OptionsPSSB007](r, key("PSS-B007"))
	merge.RegisterMergeFunc[rules.OptionsPSSB008](r, key("PSS-B008"))
	merge.RegisterMergeFunc[rules.OptionsPSSB009](r, key("PSS-B009"))
	merge.RegisterMergeFunc[rules.OptionsPSSB010](r, key("PSS-B010"))
	merge.RegisterMergeFunc[rules.OptionsPSSB011](r, key("PSS-B011"))
	merge.RegisterMergeFunc[rules.OptionsPSSB012](r, key("PSS-B012"))

	merge.RegisterMergeFunc[rules.OptionsPSSR001](r, key("PSS-R001"))
	merge.RegisterMergeFunc[rules.OptionsPSSR002](r, key("PSS-R002"))
	merge.RegisterMergeFunc[rules.OptionsPSSR003](r, key("PSS-R003"))
	merge.RegisterMergeFunc[rules.OptionsPSSR004](r, key("PSS-R004"))
	merge.RegisterMergeFunc[rules.OptionsPSSR005](r, key("PSS-R005"))
	merge.RegisterMergeFunc[rules.OptionsPSSR006](r, key("PSS-R006"))
}
