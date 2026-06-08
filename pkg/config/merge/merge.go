// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package merge

import (
	"github.com/gardener/diki/pkg/config"
)

// MergeConfigs merges two DikiConfigs. The current config is the primary config — its structure,
// providers, metadata, output, and provider/ruleset args are preserved as-is. Only ruleOptions
// within matching rulesets (matched by providerID + rulesetID + version) are merged.
//
// Merge rules for ruleOptions:
//   - Rule in current only: kept as-is
//   - Rule in base only: appended to the output
//   - Rule in both + MergeableOption: Merge() is called (base.Merge(current))
//   - Rule in both + not MergeableOption: current args win
//   - Skip always wins: if either config skips a rule, the merged result skips it
func MergeConfigs(base, current *config.DikiConfig, registry *Registry) (*config.DikiConfig, error) {
	if base == nil {
		return current, nil
	}
	if current == nil {
		return nil, nil
	}

	baseProviders := indexProviders(base.Providers)

	for pi := range current.Providers {
		currentProvider := &current.Providers[pi]
		baseProvider, found := baseProviders[currentProvider.ID]
		if !found {
			continue
		}

		baseRulesets := indexRulesets(baseProvider.Rulesets)

		for ri := range currentProvider.Rulesets {
			currentRuleset := &currentProvider.Rulesets[ri]
			rulesetKey := rulesetIndexKey{ID: currentRuleset.ID, Version: currentRuleset.Version}
			baseRuleset, found := baseRulesets[rulesetKey]
			if !found {
				continue
			}

			merged, err := mergeRuleOptions(
				baseRuleset.RuleOptions,
				currentRuleset.RuleOptions,
				currentProvider.ID,
				currentRuleset.ID,
				currentRuleset.Version,
				registry,
			)
			if err != nil {
				return nil, err
			}
			currentRuleset.RuleOptions = merged
		}
	}

	return current, nil
}

func mergeRuleOptions(
	baseOpts, currentOpts []config.RuleOptionsConfig,
	providerID, rulesetID, version string,
	registry *Registry,
) ([]config.RuleOptionsConfig, error) {
	baseByRuleID := make(map[string]config.RuleOptionsConfig, len(baseOpts))
	for _, opt := range baseOpts {
		baseByRuleID[opt.RuleID] = opt
	}

	currentRuleIDs := make(map[string]struct{}, len(currentOpts))
	merged := make([]config.RuleOptionsConfig, 0, len(currentOpts)+len(baseOpts))

	for _, currentOpt := range currentOpts {
		currentRuleIDs[currentOpt.RuleID] = struct{}{}

		baseOpt, inBase := baseByRuleID[currentOpt.RuleID]
		if !inBase {
			merged = append(merged, currentOpt)
			continue
		}

		mergedOpt, err := mergeSingleRuleOption(baseOpt, currentOpt, providerID, rulesetID, version, registry)
		if err != nil {
			return nil, err
		}
		merged = append(merged, mergedOpt)
	}

	for _, baseOpt := range baseOpts {
		if _, inCurrent := currentRuleIDs[baseOpt.RuleID]; !inCurrent {
			merged = append(merged, baseOpt)
		}
	}

	return merged, nil
}

func mergeSingleRuleOption(
	baseOpt, currentOpt config.RuleOptionsConfig,
	providerID, rulesetID, version string,
	registry *Registry,
) (config.RuleOptionsConfig, error) {
	result := config.RuleOptionsConfig{
		RuleID: currentOpt.RuleID,
	}

	result.Skip = mergeSkip(baseOpt.Skip, currentOpt.Skip)

	if baseOpt.Args == nil && currentOpt.Args == nil {
		return result, nil
	}
	if baseOpt.Args == nil {
		result.Args = currentOpt.Args
		return result, nil
	}
	if currentOpt.Args == nil {
		result.Args = baseOpt.Args
		return result, nil
	}

	key := RegistryKey{
		ProviderID: providerID,
		RulesetID:  rulesetID,
		Version:    version,
		RuleID:     currentOpt.RuleID,
	}

	mergeFn := registry.Get(key)
	if mergeFn == nil {
		result.Args = currentOpt.Args
		return result, nil
	}

	mergedArgs, err := mergeFn(baseOpt.Args, currentOpt.Args)
	if err != nil {
		return config.RuleOptionsConfig{}, err
	}
	result.Args = mergedArgs

	return result, nil
}

func mergeSkip(baseSkip, currentSkip *config.RuleOptionSkipConfig) *config.RuleOptionSkipConfig {
	if currentSkip != nil && currentSkip.Enabled {
		return currentSkip
	}
	if baseSkip != nil && baseSkip.Enabled {
		return baseSkip
	}
	return nil
}

type rulesetIndexKey struct {
	ID      string
	Version string
}

func indexProviders(providers []config.ProviderConfig) map[string]*config.ProviderConfig {
	m := make(map[string]*config.ProviderConfig, len(providers))
	for i := range providers {
		m[providers[i].ID] = &providers[i]
	}
	return m
}

func indexRulesets(rulesets []config.RulesetConfig) map[rulesetIndexKey]*config.RulesetConfig {
	m := make(map[rulesetIndexKey]*config.RulesetConfig, len(rulesets))
	for i := range rulesets {
		key := rulesetIndexKey{ID: rulesets[i].ID, Version: rulesets[i].Version}
		m[key] = &rulesets[i]
	}
	return m
}
