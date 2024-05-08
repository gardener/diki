// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"fmt"
	"log/slog"

	"k8s.io/client-go/rest"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig"
	"github.com/gardener/diki/pkg/ruleset"
)

// GardenerProviderFromConfig retuns a Provider from a ProviderConfig.
func GardenerProviderFromConfig(conf config.ProviderConfig) (provider.Provider, error) {
	p, err := gardener.FromGenericConfig(conf)
	if err != nil {
		return nil, err
	}

	setConfigDefaults(p.ShootConfig)
	setConfigDefaults(p.SeedConfig)
	providerLogger := slog.Default().With("provider", p.ID())
	setLoggerFunc := gardener.WithLogger(providerLogger)
	setLoggerFunc(p)
	rulesets := make([]ruleset.Ruleset, 0, len(conf.Rulesets))
	for _, rulesetConfig := range conf.Rulesets {
		switch rulesetConfig.ID {
		case disak8sstig.RulesetID:
			ruleset, err := disak8sstig.FromGenericConfig(rulesetConfig, p.AdditionalOpsPodLabels, p.ShootConfig, p.SeedConfig, p.Args.ShootNamespace)
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
