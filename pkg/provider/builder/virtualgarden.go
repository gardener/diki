// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"fmt"
	"log/slog"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/metadata"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/provider/virtualgarden"
	"github.com/gardener/diki/pkg/provider/virtualgarden/ruleset/disak8sstig"
	"github.com/gardener/diki/pkg/ruleset"
)

// VirtualGardenProviderFromConfig retuns a Provider from a [ProviderConfig].
func VirtualGardenProviderFromConfig(conf config.ProviderConfig) (provider.Provider, error) {
	p, err := virtualgarden.FromGenericConfig(conf)
	if err != nil {
		return nil, err
	}

	setConfigDefaults(p.RuntimeConfig)
	providerLogger := slog.Default().With("provider", p.ID())
	setLoggerFunc := virtualgarden.WithLogger(providerLogger)
	setLoggerFunc(p)
	rulesets := make([]ruleset.Ruleset, 0, len(conf.Rulesets))
	for _, rulesetConfig := range conf.Rulesets {
		switch rulesetConfig.ID {
		case disak8sstig.RulesetID:
			ruleset, err := disak8sstig.FromGenericConfig(rulesetConfig, p.AdditionalOpsPodLabels, p.RuntimeConfig)
			if err != nil {
				return nil, err
			}
			setLoggerDISA := disak8sstig.WithLogger(providerLogger.With("ruleset", ruleset.ID(), "version", ruleset.Version()))
			setLoggerDISA(ruleset)
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

// virtualGardenGetSupportedVersions returns the supported versions of a specific ruleset that is supported by the Virtual Garden provider.
func virtualGardenGetSupportedVersions(ruleset string) []string {
	switch ruleset {
	case disak8sstig.RulesetID:
		return disak8sstig.SupportedVersions
	default:
		return nil
	}
}

// VirtualGardenProviderMetadata returns available metadata for the Virtual Garden Provider and it's supported rulesets.
func VirtualGardenProviderMetadata() metadata.ProviderMetadata {
	providerMetadata := metadata.ProviderMetadata{}
	providerMetadata.ProviderID = "virtualgarden"
	providerMetadata.ProviderName = "Virtual Garden"

	var availableRulesets = map[string]string{
		disak8sstig.RulesetID: disak8sstig.RulesetName,
	}

	for rulesetID, rulesetName := range availableRulesets {
		rulesetMetadata := &metadata.RulesetMetadata{}
		rulesetMetadata.RulesetID = rulesetID
		rulesetMetadata.RulesetName = rulesetName
		rulesetSupportedVersions := virtualGardenGetSupportedVersions(rulesetMetadata.RulesetID)
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
