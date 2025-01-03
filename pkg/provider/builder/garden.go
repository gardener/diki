// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"fmt"
	"log/slog"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/metadata"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/provider/garden"
	"github.com/gardener/diki/pkg/provider/garden/ruleset/securityhardenedshoot"
	"github.com/gardener/diki/pkg/ruleset"
)

// GardenProviderFromConfig retuns a Provider from a [ProviderConfig].
func GardenProviderFromConfig(conf config.ProviderConfig) (provider.Provider, error) {
	p, err := garden.FromGenericConfig(conf)
	if err != nil {
		return nil, err
	}

	setConfigDefaults(p.Config)
	providerLogger := slog.Default().With("provider", p.ID())
	setLoggerFunc := garden.WithLogger(providerLogger)
	setLoggerFunc(p)
	rulesets := make([]ruleset.Ruleset, 0, len(conf.Rulesets))
	for _, rulesetConfig := range conf.Rulesets {
		switch rulesetConfig.ID {
		case securityhardenedshoot.RulesetID:
			ruleset, err := securityhardenedshoot.FromGenericConfig(rulesetConfig, p.Config)
			if err != nil {
				return nil, err
			}
			setLoggerHardened := securityhardenedshoot.WithLogger(providerLogger.With("ruleset", ruleset.ID(), "version", ruleset.Version()))
			setLoggerHardened(ruleset)
			rulesets = append(rulesets, ruleset)
		default:
			return nil, fmt.Errorf("unknown ruleset identifier: %s", rulesetConfig.ID)
		}
	}

	if err := p.AddRulesets(rulesets...); err != nil {
		return nil, err
	}

	return p, nil
}

// gardenGetSupportedVersions returns the Supported Versions of a specific ruleset that is supported by the Garden provider.
func gardenGetSupportedVersions(ruleset string) []string {
	switch ruleset {
	case securityhardenedshoot.RulesetID:
		return securityhardenedshoot.SupportedVersions
	default:
		return nil
	}
}

// GardenProviderMetadata returns available metadata for the Garden Provider and it's supported rulesets.
func GardenProviderMetadata() metadata.ProviderDetailed {
	providerMetadata := metadata.ProviderDetailed{
		Provider: metadata.Provider{
			ID:   garden.ProviderID,
			Name: garden.ProviderName,
		},
		Rulesets: []metadata.Ruleset{
			{
				ID:   securityhardenedshoot.RulesetID,
				Name: securityhardenedshoot.RulesetName,
			},
		},
	}

	for i := range providerMetadata.Rulesets {
		supportedVersions := gardenGetSupportedVersions(providerMetadata.Rulesets[i].ID)
		for _, supportedVersion := range supportedVersions {
			providerMetadata.Rulesets[i].Versions = append(
				providerMetadata.Rulesets[i].Versions,
				metadata.Version{Version: supportedVersion, Latest: false},
			)
		}

		// Mark the first version as latest as the versions are sorted from newest to oldest
		if len(providerMetadata.Rulesets[i].Versions) > 0 {
			providerMetadata.Rulesets[i].Versions[0].Latest = true
		}
	}

	return providerMetadata
}
