// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"fmt"
	"log/slog"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/provider/garden"
	"github.com/gardener/diki/pkg/provider/garden/ruleset/hardenedgardenershoot"
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
		case hardenedgardenershoot.RulesetID:
			ruleset, err := hardenedgardenershoot.FromGenericConfig(rulesetConfig, p.AdditionalOpsPodLabels, p.Config)
			if err != nil {
				return nil, err
			}
			setLoggerHardened := hardenedgardenershoot.WithLogger(providerLogger.With("ruleset", ruleset.ID(), "version", ruleset.Version()))
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
