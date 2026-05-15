// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package merge

import (
	"github.com/gardener/diki/pkg/config"
)

// MergeConfigs merges two DikiConfigs. The custom config is the primary config — its structure,
// providers, metadata, output, and provider/ruleset args are preserved as-is. Only ruleOptions
// within matching rulesets (matched by providerID + rulesetID + version) are merged.
//
// Merge rules for ruleOptions:
//   - Rule in custom only: kept as-is
//   - Rule in base only: appended to the output
//   - Rule in both + MergeableOption: Merge() is called (base.Merge(custom))
//   - Rule in both + not MergeableOption: custom args win
//   - Skip always wins: if either config skips a rule, the merged result skips it
func MergeConfigs(base, custom *config.DikiConfig, registry *Registry) (*config.DikiConfig, error) {
	if base == nil {
		return custom, nil
	}
	if custom == nil {
		return custom, nil
	}

	baseProviders := indexProviders(base.Providers)

	for pi := range custom.Providers {
		customProvider := &custom.Providers[pi]
		baseProvider, found := baseProviders[customProvider.ID]
		if !found {
			continue
		}

		baseRulesets := indexRulesets(baseProvider.Rulesets)

		for ri := range customProvider.Rulesets {
			customRuleset := &customProvider.Rulesets[ri]
			rulesetKey := rulesetIndexKey{ID: customRuleset.ID, Version: customRuleset.Version}
			baseRuleset, found := baseRulesets[rulesetKey]
			if !found {
				continue
			}

			merged, err := mergeRuleOptions(
				baseRuleset.RuleOptions,
				customRuleset.RuleOptions,
				customProvider.ID,
				customRuleset.ID,
				customRuleset.Version,
				registry,
			)
			if err != nil {
				return nil, err
			}
			customRuleset.RuleOptions = merged
		}
	}

	return custom, nil
}

func mergeRuleOptions(
	baseOpts, customOpts []config.RuleOptionsConfig,
	providerID, rulesetID, version string,
	registry *Registry,
) ([]config.RuleOptionsConfig, error) {
	baseByRuleID := make(map[string]config.RuleOptionsConfig, len(baseOpts))
	for _, opt := range baseOpts {
		baseByRuleID[opt.RuleID] = opt
	}

	customRuleIDs := make(map[string]struct{}, len(customOpts))
	merged := make([]config.RuleOptionsConfig, 0, len(customOpts)+len(baseOpts))

	for _, customOpt := range customOpts {
		customRuleIDs[customOpt.RuleID] = struct{}{}

		baseOpt, inBase := baseByRuleID[customOpt.RuleID]
		if !inBase {
			merged = append(merged, customOpt)
			continue
		}

		mergedOpt, err := mergeSingleRuleOption(baseOpt, customOpt, providerID, rulesetID, version, registry)
		if err != nil {
			return nil, err
		}
		merged = append(merged, mergedOpt)
	}

	for _, baseOpt := range baseOpts {
		if _, inCustom := customRuleIDs[baseOpt.RuleID]; !inCustom {
			merged = append(merged, baseOpt)
		}
	}

	return merged, nil
}

func mergeSingleRuleOption(
	baseOpt, customOpt config.RuleOptionsConfig,
	providerID, rulesetID, version string,
	registry *Registry,
) (config.RuleOptionsConfig, error) {
	result := config.RuleOptionsConfig{
		RuleID: customOpt.RuleID,
	}

	result.Skip = mergeSkip(baseOpt.Skip, customOpt.Skip)

	if baseOpt.Args == nil && customOpt.Args == nil {
		return result, nil
	}
	if baseOpt.Args == nil {
		result.Args = customOpt.Args
		return result, nil
	}
	if customOpt.Args == nil {
		result.Args = baseOpt.Args
		return result, nil
	}

	key := RegistryKey{
		ProviderID: providerID,
		RulesetID:  rulesetID,
		Version:    version,
		RuleID:     customOpt.RuleID,
	}

	mergeFn := registry.Get(key)
	if mergeFn == nil {
		result.Args = customOpt.Args
		return result, nil
	}

	mergedArgs, err := mergeFn(baseOpt.Args, customOpt.Args)
	if err != nil {
		return config.RuleOptionsConfig{}, err
	}
	result.Args = mergedArgs

	return result, nil
}

func mergeSkip(baseSkip, customSkip *config.RuleOptionSkipConfig) *config.RuleOptionSkipConfig {
	if customSkip != nil && customSkip.Enabled {
		return customSkip
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
