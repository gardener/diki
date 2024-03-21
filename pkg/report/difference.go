// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"cmp"
	"errors"
	"slices"
	"time"

	"github.com/gardener/diki/pkg/rule"
)

// Difference contains the difference between 2 reports.
type Difference struct {
	Time      time.Time            `json:"time"`
	MinStatus rule.Status          `json:"minStatus,omitempty"`
	Providers []ProviderDifference `json:"providers"`
}

// ProviderDifference contains the difference between 2 reports
// for a known provider and its ran rulesets.
type ProviderDifference struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	OldMetadata map[string]string   `json:"oldMetadata,omitempty"`
	NewMetadata map[string]string   `json:"newMetadata,omitempty"`
	Rulesets    []RulesetDifference `json:"rulesets"`
}

// RulesetDifference contains the difference between 2 reports
// for a ruleset and its rules.
type RulesetDifference struct {
	ID      string           `json:"id"`
	Name    string           `json:"name"`
	Version string           `json:"version"`
	Rules   []RuleDifference `json:"rules"`
}

// RuleDifference contains the difference between 2 reports for a single rule.
type RuleDifference struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Added   []Check `json:"added,omitempty"`
	Removed []Check `json:"removed,omitempty"`
}

// CreateDifference creates the difference between 2 reports.
func CreateDifference(oldReport Report, newReport Report) (*Difference, error) {
	var minStatus rule.Status
	switch {
	case oldReport.MinStatus == newReport.MinStatus:
		minStatus = oldReport.MinStatus
	case len(oldReport.MinStatus) == 0:
		minStatus = newReport.MinStatus
	case len(newReport.MinStatus) == 0:
		minStatus = oldReport.MinStatus
	default:
		return nil, errors.New("reports must have equal minStatus")
	}

	diff := &Difference{
		Time:      time.Now(),
		MinStatus: minStatus,
		Providers: []ProviderDifference{},
	}

	providers := getUniqueProviders(oldReport.Providers, newReport.Providers)

	for _, provider := range providers {
		oldProviderIdx := slices.IndexFunc(oldReport.Providers, func(p Provider) bool {
			return p.ID == provider
		})

		oldProvider := Provider{}
		if oldProviderIdx >= 0 {
			oldProvider = oldReport.Providers[oldProviderIdx]
		}

		newProviderIdx := slices.IndexFunc(newReport.Providers, func(p Provider) bool {
			return p.ID == provider
		})

		newProvider := Provider{}
		if newProviderIdx >= 0 {
			newProvider = newReport.Providers[newProviderIdx]
		}

		rulesets := getUniqueRulesets(oldProvider.Rulesets, newProvider.Rulesets)

		var rulesetDiff []RulesetDifference
		for id, versions := range rulesets {
			for _, version := range versions {
				oldRulesetIdx := slices.IndexFunc(oldProvider.Rulesets, func(r Ruleset) bool {
					return r.ID == id && r.Version == version
				})

				oldRuleset := Ruleset{}
				if oldRulesetIdx >= 0 {
					oldRuleset = oldProvider.Rulesets[oldRulesetIdx]
				}

				newRulesetIdx := slices.IndexFunc(newProvider.Rulesets, func(r Ruleset) bool {
					return r.ID == id && r.Version == version
				})

				newRuleset := Ruleset{}
				if newRulesetIdx >= 0 {
					newRuleset = newProvider.Rulesets[newRulesetIdx]
				}

				rulesetName := newRuleset.Name
				if len(rulesetName) == 0 {
					rulesetName = oldRuleset.Name
				}
				rulesetDiff = append(rulesetDiff, RulesetDifference{
					ID:      id,
					Name:    rulesetName,
					Version: version,
					Rules:   getRulesDifference(oldRuleset.Rules, newRuleset.Rules),
				})
			}
		}

		// sort ruleset alphabetically to ensure static order
		slices.SortFunc(rulesetDiff, func(a, b RulesetDifference) int {
			return cmp.Compare(a.ID, b.ID)
		})

		var (
			oldMetadata = map[string]string{}
			newMetadata = map[string]string{}
		)

		for k, v := range oldProvider.Metadata {
			oldMetadata[k] = v
		}
		for k, v := range newProvider.Metadata {
			newMetadata[k] = v
		}

		oldMetadata["time"] = oldReport.Time.Format(time.RFC3339)
		newMetadata["time"] = newReport.Time.Format(time.RFC3339)

		providerName := newProvider.Name
		if len(providerName) == 0 {
			providerName = oldProvider.Name
		}
		diff.Providers = append(diff.Providers, ProviderDifference{
			ID:          provider,
			Name:        providerName,
			OldMetadata: oldMetadata,
			NewMetadata: newMetadata,
			Rulesets:    rulesetDiff,
		})
	}
	return diff, nil
}

func getRulesDifference(oldRules, newRules []Rule) []RuleDifference {
	var (
		ruleDiff      []RuleDifference
		addedChecks   = getCheckDifference(newRules, oldRules)
		removedChecks = getCheckDifference(oldRules, newRules)
	)

	for _, newCheck := range addedChecks {
		ruleDiff = append(ruleDiff, RuleDifference{
			ID:    newCheck.ID,
			Name:  newCheck.Name,
			Added: newCheck.Checks,
		})
	}

	for _, removedCheck := range removedChecks {
		idx := slices.IndexFunc(ruleDiff, func(r RuleDifference) bool {
			return r.ID == removedCheck.ID
		})

		if idx >= 0 {
			ruleDiff[idx].Removed = removedCheck.Checks
			continue
		}

		ruleDiff = append(ruleDiff, RuleDifference{
			ID:      removedCheck.ID,
			Name:    removedCheck.Name,
			Removed: removedCheck.Checks,
		})
	}

	// sort rules by id
	slices.SortFunc(ruleDiff, func(a, b RuleDifference) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return ruleDiff
}

// getCheckDifference returns all rules with checks
// that are present in rules1 but missing in rules2
func getCheckDifference(rules1, rules2 []Rule) []Rule {
	var uniqueRulesChecks []Rule
	for _, rule1 := range rules1 {
		var (
			checks2    []Check
			difference []Check
		)
		rules2Idx := slices.IndexFunc(rules2, func(r Rule) bool {
			return r.ID == rule1.ID
		})

		if rules2Idx >= 0 {
			checks2 = rules2[rules2Idx].Checks
		}

		for _, check1 := range rule1.Checks {
			oldCheckIdx := slices.IndexFunc(checks2, func(c Check) bool {
				return c.Status == check1.Status && c.Message == check1.Message
			})

			if oldCheckIdx < 0 {
				// we do not want targets in diff since they are not taken into account
				check1.Targets = nil
				difference = append(difference, check1)
			}
		}

		if len(difference) > 0 {
			uniqueRulesChecks = append(uniqueRulesChecks, Rule{
				ID:     rule1.ID,
				Name:   rule1.Name,
				Checks: difference,
			})
		}
	}

	return uniqueRulesChecks
}

// getUniqueProviders returns a list of all unique
// provider IDs contained in ps1 and ps2.
func getUniqueProviders(ps1, ps2 []Provider) []string {
	var ps []string
	for _, p1 := range ps1 {
		ps = append(ps, p1.ID)
	}

	for _, p2 := range ps2 {
		p1Idx := slices.IndexFunc(ps1, func(p1 Provider) bool {
			return p2.ID == p1.ID
		})

		if p1Idx < 0 {
			ps = append(ps, p2.ID)
		}
	}
	return ps
}

// getUniqueRulesets returns a map of all unique rulesets,
// where the maps keys are ruleset IDs and the values are a
// list of all unique versions in rss1 and rss2.
func getUniqueRulesets(rss1, rss2 []Ruleset) map[string][]string {
	rss := map[string][]string{}
	for _, rs1 := range rss1 {
		rss[rs1.ID] = append(rss[rs1.ID], rs1.Version)
	}

	for _, rs2 := range rss2 {
		rs1Idx := slices.IndexFunc(rss1, func(rs1 Ruleset) bool {
			return rs2.ID == rs1.ID && rs2.Version == rs1.Version
		})

		if rs1Idx < 0 {
			rss[rs2.ID] = append(rss[rs2.ID], rs2.Version)
		}
	}
	return rss
}
