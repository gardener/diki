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
	"github.com/gardener/diki/pkg/provider/managedk8s"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s"
	"github.com/gardener/diki/pkg/ruleset"
)

// ManagedK8SProviderFromConfig retuns a Provider from a [ProviderConfig].
func ManagedK8SProviderFromConfig(conf config.ProviderConfig) (provider.Provider, error) {
	p, err := managedk8s.FromGenericConfig(conf)
	if err != nil {
		return nil, err
	}

	setConfigDefaults(p.Config)
	providerLogger := slog.Default().With("provider", p.ID())
	setLoggerFunc := managedk8s.WithLogger(providerLogger)
	setLoggerFunc(p)
	rulesets := make([]ruleset.Ruleset, 0, len(conf.Rulesets))
	for _, rulesetConfig := range conf.Rulesets {
		switch rulesetConfig.ID {
		case disak8sstig.RulesetID:
			ruleset, err := disak8sstig.FromGenericConfig(rulesetConfig, p.AdditionalOpsPodLabels, p.Config)
			if err != nil {
				return nil, err
			}
			setLoggerDISA := disak8sstig.WithLogger(providerLogger.With("ruleset", ruleset.ID(), "version", ruleset.Version()))
			setLoggerDISA(ruleset)
			rulesets = append(rulesets, ruleset)
		case securityhardenedk8s.RulesetID:
			ruleset, err := securityhardenedk8s.FromGenericConfig(rulesetConfig, p.Config)
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
func ManagedK8SProviderMetadata() metadata.ProviderMetadata {
	providerMetadata := metadata.ProviderMetadata{}
	providerMetadata.ProviderID = "managedk8s"
	providerMetadata.ProviderName = "Managed Kubernetes"

	var availableRulesets = map[string]string{
		securityhardenedk8s.RulesetID: securityhardenedk8s.RulesetName,
		disak8sstig.RulesetID:         disak8sstig.RulesetName,
	}

	for rulesetID, rulesetName := range availableRulesets {
		rulesetMetadata := &metadata.RulesetMetadata{}
		rulesetMetadata.RulesetID = rulesetID
		rulesetMetadata.RulesetName = rulesetName
		rulesetSupportedVersions := managedK8SGetSupportedVersions(rulesetMetadata.RulesetID)
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
