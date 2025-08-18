// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"fmt"
	"log/slog"

	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/metadata"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/provider/managedk8s"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s"
	"github.com/gardener/diki/pkg/ruleset"
)

// ManagedK8SProviderFromConfig returns a Provider from a [ProviderConfig].
func ManagedK8SProviderFromConfig(conf config.ProviderConfig, fldPath *field.Path) (provider.Provider, error) {
	p, err := managedk8s.FromGenericConfig(conf)
	if err != nil {
		return nil, err
	}

	rulesetsPath := fldPath.Child("rulesets")

	setConfigDefaults(p.Config)
	providerLogger := slog.Default().With("provider", p.ID())
	setLoggerFunc := managedk8s.WithLogger(providerLogger)
	setLoggerFunc(p)
	rulesets := make([]ruleset.Ruleset, 0, len(conf.Rulesets))
	for rulesetIdx, rulesetConfig := range conf.Rulesets {
		switch rulesetConfig.ID {
		case disak8sstig.RulesetID:
			ruleset, err := disak8sstig.FromGenericConfig(rulesetConfig, p.AdditionalOpsPodLabels, p.Config, rulesetsPath.Index(rulesetIdx))
			if err != nil {
				return nil, err
			}
			setLoggerDISA := disak8sstig.WithLogger(providerLogger.With("ruleset", ruleset.ID(), "version", ruleset.Version()))
			setLoggerDISA(ruleset)
			rulesets = append(rulesets, ruleset)
		case securityhardenedk8s.RulesetID:
			ruleset, err := securityhardenedk8s.FromGenericConfig(rulesetConfig, p.Config, rulesetsPath.Index(rulesetIdx))
			if err != nil {
				return nil, err
			}
			setLoggerHardened := securityhardenedk8s.WithLogger(providerLogger.With("ruleset", ruleset.ID(), "version", ruleset.Version()))
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

// managedK8SGetSupportedVersions returns the supported versions of a specific ruleset that is supported by the Managed K8S provider.
func managedK8SGetSupportedVersions(ruleset string) []string {
	switch ruleset {
	case securityhardenedk8s.RulesetID:
		return securityhardenedk8s.SupportedVersions
	case disak8sstig.RulesetID:
		return disak8sstig.SupportedVersions
	default:
		return nil
	}
}

// ManagedK8SProviderMetadata returns available metadata for the Managed Kubernetes Provider and it's supported rulesets.
func ManagedK8SProviderMetadata() metadata.ProviderDetailed {
	providerMetadata := metadata.ProviderDetailed{
		Provider: metadata.Provider{
			ID:   managedk8s.ProviderID,
			Name: managedk8s.ProviderName,
		},
		Rulesets: []metadata.Ruleset{
			{
				ID:   securityhardenedk8s.RulesetID,
				Name: securityhardenedk8s.RulesetName,
			},
			{
				ID:   disak8sstig.RulesetID,
				Name: disak8sstig.RulesetName,
			},
		},
	}

	for i := range providerMetadata.Rulesets {
		supportedVersions := managedK8SGetSupportedVersions(providerMetadata.Rulesets[i].ID)
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
