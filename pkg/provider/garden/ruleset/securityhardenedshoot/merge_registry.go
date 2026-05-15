// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package securityhardenedshoot

import (
	"github.com/gardener/diki/pkg/config/merge"
	"github.com/gardener/diki/pkg/provider/garden"
	"github.com/gardener/diki/pkg/provider/garden/ruleset/securityhardenedshoot/rules"
)

// RegisterMergeFuncs registers all rule option merge functions for the
// Security Hardened Shoot Cluster ruleset (garden provider).
func RegisterMergeFuncs(r *merge.Registry) {
	for _, version := range SupportedVersions {
		switch version {
		case "v0.2.1", "v0.2.0":
			registerV02MergeFuncs(r, version)
		case "v0.1.0":
			registerV01MergeFuncs(r, version)
		}
	}
}

func registerV02MergeFuncs(r *merge.Registry, version string) {
	key := func(ruleID string) merge.RegistryKey {
		return merge.RegistryKey{
			ProviderID: garden.ProviderID,
			RulesetID:  RulesetID,
			Version:    version,
			RuleID:     ruleID,
		}
	}

	merge.RegisterMergeFunc[rules.Options1000](r, key("1000"))
	merge.RegisterMergeFunc[rules.Options1001](r, key("1001"))
	merge.RegisterMergeFunc[rules.Options1002](r, key("1002"))
	merge.RegisterMergeFunc[rules.Options1003](r, key("1003"))
	merge.RegisterMergeFunc[rules.Options2000](r, key("2000"))
	merge.RegisterMergeFunc[rules.Options2007](r, key("2007"))
}

func registerV01MergeFuncs(r *merge.Registry, version string) {
	key := func(ruleID string) merge.RegistryKey {
		return merge.RegistryKey{
			ProviderID: garden.ProviderID,
			RulesetID:  RulesetID,
			Version:    version,
			RuleID:     ruleID,
		}
	}

	merge.RegisterMergeFunc[rules.Options1000](r, key("1000"))
	merge.RegisterMergeFunc[rules.Options2000](r, key("2000"))
	merge.RegisterMergeFunc[rules.Options2007](r, key("2007"))
}
