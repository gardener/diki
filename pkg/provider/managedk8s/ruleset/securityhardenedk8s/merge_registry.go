// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package securityhardenedk8s

import (
	"github.com/gardener/diki/pkg/config/merge"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s/rules"
)

// RegisterMergeFuncs registers all rule option merge functions for the
// Security Hardened Kubernetes Cluster ruleset (managedk8s provider).
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

	merge.RegisterMergeFunc[rules.Options2000](r, key("2000"))
	merge.RegisterMergeFunc[rules.Options2001](r, key("2001"))
	merge.RegisterMergeFunc[rules.Options2002](r, key("2002"))
	merge.RegisterMergeFunc[rules.Options2003](r, key("2003"))
	merge.RegisterMergeFunc[rules.Options2004](r, key("2004"))
	merge.RegisterMergeFunc[rules.Options2005](r, key("2005"))
	merge.RegisterMergeFunc[rules.Options2006](r, key("2006"))
	merge.RegisterMergeFunc[rules.Options2007](r, key("2007"))
	merge.RegisterMergeFunc[rules.Options2008](r, key("2008"))
}
