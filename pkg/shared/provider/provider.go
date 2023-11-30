// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/ruleset"
)

// Logger is a minimalistic logger interface.
type Logger interface {
	Info(string, ...any)
	Error(string, ...any)
}

// RunAll is a sample implementation for a [provider.Provider].
func RunAll(ctx context.Context, p provider.Provider, rulesets map[string]ruleset.Ruleset, log Logger) (provider.ProviderResult, error) {
	if len(rulesets) == 0 {
		return provider.ProviderResult{}, fmt.Errorf("no rulests are registered with the provider")
	}

	result := provider.ProviderResult{
		ProviderName:   p.Name(),
		ProviderID:     p.ID(),
		Metadata:       maps.Clone(p.Metadata()),
		RulesetResults: make([]ruleset.RulesetResult, 0, len(rulesets)),
	}

	var errAgg error
	log.Info(fmt.Sprintf("provider will run %d rulesets", len(rulesets)))
	for _, rs := range rulesets {
		log.Info(fmt.Sprintf("starting run of ruleset %s version %s", rs.ID(), rs.Version()))
		if res, err := rs.Run(ctx); err != nil {
			errAgg = errors.Join(errAgg, fmt.Errorf("ruleset with id %s and version %s errored: %w", res.RulesetID, res.RulesetVersion, err))
			log.Error(fmt.Sprintf("finished ruleset %s version %s run", rs.ID(), rs.Version()), "error", err)
		} else {
			result.RulesetResults = append(result.RulesetResults, res)
			log.Info(fmt.Sprintf("finished ruleset %s version %s run", rs.ID(), rs.Version()))
		}
	}

	if errAgg != nil {
		return provider.ProviderResult{}, errAgg
	}
	return result, nil
}
