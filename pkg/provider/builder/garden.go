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
func GardenProviderMetadata() metadata.ProviderMetadata {
	providerMetadata := metadata.ProviderMetadata{}
	providerMetadata.ProviderID = "garden"
	providerMetadata.ProviderName = "Garden"

	var availableRulesets = map[string]string{
		securityhardenedshoot.RulesetID: securityhardenedshoot.RulesetName,
	}

	for rulesetID, rulesetName := range availableRulesets {
		rulesetMetadata := &metadata.RulesetMetadata{}
		rulesetMetadata.RulesetID = rulesetID
		rulesetMetadata.RulesetName = rulesetName
		rulesetSupportedVersions := gardenGetSupportedVersions(rulesetMetadata.RulesetID)
		for index, supportedVersion := range rulesetSupportedVersions {
			if index == 0 {
				rulesetMetadata.Versions = append(rulesetMetadata.Versions, metadata.Version{Version: supportedVersion, Latest: true})
			} else {
				rulesetMetadata.Versions = append(rulesetMetadata.Versions, metadata.Version{Version: supportedVersion, Latest: false})
			}
		}
		providerMetadata.ProviderRulesets = append(providerMetadata.ProviderRulesets, *rulesetMetadata)
	}

	return providerMetadata
}
