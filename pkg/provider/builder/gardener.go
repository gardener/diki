// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"fmt"
	"log/slog"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/rest"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/metadata"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig"
	"github.com/gardener/diki/pkg/ruleset"
)

// GardenerProviderFromConfig returns a Provider from a ProviderConfig.
func GardenerProviderFromConfig(conf config.ProviderConfig, fldPath *field.Path) (provider.Provider, error) {
	p, err := gardener.FromGenericConfig(conf)
	if err != nil {
		return nil, err
	}

	rulesetsPath := fldPath.Child("rulesets")

	setConfigDefaults(p.ShootConfig)
	setConfigDefaults(p.SeedConfig)
	providerLogger := slog.Default().With("provider", p.ID())
	setLoggerFunc := gardener.WithLogger(providerLogger)
	setLoggerFunc(p)
	rulesets := make([]ruleset.Ruleset, 0, len(conf.Rulesets))
	for rulesetIdx, rulesetConfig := range conf.Rulesets {
		switch rulesetConfig.ID {
		case disak8sstig.RulesetID:
			ruleset, err := disak8sstig.FromGenericConfig(rulesetConfig, p.AdditionalOpsPodLabels, p.ShootConfig, p.SeedConfig, p.Args.ShootNamespace, *rulesetsPath.Index(rulesetIdx))
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

func setConfigDefaults(config *rest.Config) {
	if config.QPS <= 0 {
		config.QPS = 20
	}

	if config.Burst <= 0 {
		config.Burst = 40
	}
}

// gardenerGetSupportedVersions returns the Supported Versions of a specific ruleset that is supported by the Gardener provider.
func gardenerGetSupportedVersions(ruleset string) []string {
	switch ruleset {
	case disak8sstig.RulesetID:
		return disak8sstig.SupportedVersions
	default:
		return nil
	}
}

// GardenerProviderMetadata returns available metadata for the Gardener Provider and it's supported rulesets.
func GardenerProviderMetadata() metadata.ProviderDetailed {
	providerMetadata := metadata.ProviderDetailed{
		Provider: metadata.Provider{
			ID:   gardener.ProviderID,
			Name: gardener.ProviderName,
		},
		Rulesets: []metadata.Ruleset{
			{
				ID:   disak8sstig.RulesetID,
				Name: disak8sstig.RulesetName,
			},
		},
	}

	for i := range providerMetadata.Rulesets {
		supportedVersions := gardenerGetSupportedVersions(providerMetadata.Rulesets[i].ID)
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
