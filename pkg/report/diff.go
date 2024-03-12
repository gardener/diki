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

// Diff contains the difference in 2 reports
type Diff struct {
	Time      time.Time      `json:"time"`
	MinStatus rule.Status    `json:"minStatus,omitempty"`
	Providers []ProviderDiff `json:"providers"`
}

// ProviderDiff contains the difference in 2 reports
// for a known provider and its ran rulesets.
type ProviderDiff struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	OldMetadata map[string]string `json:"oldMetadata,omitempty"`
	NewMetadata map[string]string `json:"newMetadata,omitempty"`
	Rulesets    []RulesetDiff     `json:"rulesets"`
}

// RulesetDiff contains the difference in 2 reports
// for a ruleset and its rules.
type RulesetDiff struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	Version string     `json:"version"`
	Rules   []RuleDiff `json:"rules"`
}

// RuleDiff contains the difference in 2 reports for a single rule.
type RuleDiff struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Added   []Check `json:"added,omitempty"`
	Removed []Check `json:"removed,omitempty"`
}

func getUniqueChecks(rules1, rules2 []Rule) []Rule {
	var uniqueRulesChecks []Rule
	for _, rule1 := range rules1 {
		var (
			checks2      []Check
			uniqueChecks []Check
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
				uniqueChecks = append(uniqueChecks, check1)
			}
		}

		if len(uniqueChecks) > 0 {
			uniqueRulesChecks = append(uniqueRulesChecks, Rule{
				ID:     rule1.ID,
				Name:   rule1.Name,
				Checks: uniqueChecks,
			})
		}
	}

	return uniqueRulesChecks
}

func getRulesDiff(oldRules, newRules []Rule) []RuleDiff {
	var (
		ruleDiff      []RuleDiff
		addedChecks   = getUniqueChecks(newRules, oldRules)
		removedChecks = getUniqueChecks(oldRules, newRules)
	)

	for _, newCheck := range addedChecks {
		ruleDiff = append(ruleDiff, RuleDiff{
			ID:    newCheck.ID,
			Name:  newCheck.Name,
			Added: newCheck.Checks,
		})
	}

	for _, removedCheck := range removedChecks {
		idx := slices.IndexFunc(ruleDiff, func(r RuleDiff) bool {
			return r.ID == removedCheck.ID
		})

		if idx >= 0 {
			ruleDiff[idx].Removed = removedCheck.Checks
			continue
		}

		ruleDiff = append(ruleDiff, RuleDiff{
			ID:      removedCheck.ID,
			Name:    removedCheck.Name,
			Removed: removedCheck.Checks,
		})
	}

	// sort rules by id
	slices.SortFunc(ruleDiff, func(a, b RuleDiff) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return ruleDiff
}

// CreateDiff created the diff of 2 reports.
func CreateDiff(oldReport Report, newReport Report) (*Diff, error) {
	if oldReport.MinStatus != newReport.MinStatus {
		return nil, errors.New("reports must have equal minStatus")
	}

	diff := &Diff{
		Time:      time.Now(),
		MinStatus: oldReport.MinStatus,
		Providers: []ProviderDiff{},
	}

	for _, provider := range newReport.Providers {
		oldProviderIdx := slices.IndexFunc(oldReport.Providers, func(p Provider) bool {
			return p.ID == provider.ID
		})

		if oldProviderIdx >= 0 {
			var rulesetDiff []RulesetDiff
			for _, ruleset := range provider.Rulesets {
				oldRulesetIdx := slices.IndexFunc(oldReport.Providers[oldProviderIdx].Rulesets, func(r Ruleset) bool {
					return r.ID == ruleset.ID && r.Version == ruleset.Version
				})

				if oldRulesetIdx >= 0 {
					rulesetDiff = append(rulesetDiff, RulesetDiff{
						ID:      ruleset.ID,
						Name:    ruleset.Name,
						Version: ruleset.Version,
						Rules:   getRulesDiff(oldReport.Providers[oldProviderIdx].Rulesets[oldRulesetIdx].Rules, ruleset.Rules),
					})
				}
			}
			oldReport.Providers[oldProviderIdx].Metadata["time"] = oldReport.Time.Format(time.RFC3339)
			provider.Metadata["time"] = oldReport.Time.Format(time.RFC3339)

			diff.Providers = append(diff.Providers, ProviderDiff{
				ID:          provider.ID,
				Name:        provider.Name,
				OldMetadata: oldReport.Providers[oldProviderIdx].Metadata,
				NewMetadata: provider.Metadata,
				Rulesets:    rulesetDiff,
			})
		}
	}
	return diff, nil
}
