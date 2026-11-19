// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package podsecuritystandards

import (
	"github.com/gardener/diki/pkg/config/merge"
)

// RegisterMergeFuncs registers all rule option merge functions for the
// Pod Security Standards ruleset (managedk8s provider).
func RegisterMergeFuncs(r *merge.Registry) {
	for _, version := range SupportedVersions {
		registerV01MergeFuncs(r, version)
	}
}

func registerV01MergeFuncs(_ *merge.Registry, version string) {
	key := func(ruleID string) merge.RegistryKey {
		return merge.RegistryKey{
			ProviderID: "managedk8s",
			RulesetID:  RulesetID,
			Version:    version,
			RuleID:     ruleID,
		}
	}

	_ = key
}
