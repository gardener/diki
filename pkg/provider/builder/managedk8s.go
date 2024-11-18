// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"fmt"
	"log/slog"

	"github.com/gardener/diki/pkg/config"
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
