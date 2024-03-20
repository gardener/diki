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
	Time      time.Time      `json:"time"`
	MinStatus rule.Status    `json:"minStatus,omitempty"`
	Providers []ProviderDiff `json:"providers"`
}

// ProviderDiff contains the difference between 2 reports
// for a known provider and its ran rulesets.
type ProviderDiff struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	OldMetadata map[string]string `json:"oldMetadata,omitempty"`
	NewMetadata map[string]string `json:"newMetadata,omitempty"`
	Rulesets    []RulesetDiff     `json:"rulesets"`
}

// RulesetDiff contains the difference between 2 reports
// for a ruleset and its rules.
type RulesetDiff struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	Version string     `json:"version"`
	Rules   []RuleDiff `json:"rules"`
}

// RuleDiff contains the difference between 2 reports for a single rule.
type RuleDiff struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Added   []Check `json:"added,omitempty"`
	Removed []Check `json:"removed,omitempty"`
}

// CreateDiff creates the difference between 2 reports.
func CreateDiff(oldReport Report, newReport Report) (*Difference, error) {
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
		Providers: []ProviderDiff{},
	}

	for _, newProvider := range newReport.Providers {
		oldProviderIdx := slices.IndexFunc(oldReport.Providers, func(p Provider) bool {
			return p.ID == newProvider.ID
		})

		oldProvider := Provider{}
		if oldProviderIdx >= 0 {
			oldProvider = oldReport.Providers[oldProviderIdx]
		}

		var rulesetDiff []RulesetDiff
		for _, newRuleset := range newProvider.Rulesets {
			oldRulesetIdx := slices.IndexFunc(oldProvider.Rulesets, func(r Ruleset) bool {
				return r.ID == newRuleset.ID && r.Version == newRuleset.Version
			})

			oldRuleset := Ruleset{}
			if oldRulesetIdx >= 0 {
				oldRuleset = oldProvider.Rulesets[oldRulesetIdx]
			}

			rulesetDiff = append(rulesetDiff, RulesetDiff{
				ID:      newRuleset.ID,
				Name:    newRuleset.Name,
				Version: newRuleset.Version,
				Rules:   getRulesDiff(oldRuleset.Rules, newRuleset.Rules),
			})
		}

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
		newMetadata["time"] = oldReport.Time.Format(time.RFC3339)

		diff.Providers = append(diff.Providers, ProviderDiff{
			ID:          newProvider.ID,
			Name:        newProvider.Name,
			OldMetadata: oldMetadata,
			NewMetadata: newMetadata,
			Rulesets:    rulesetDiff,
		})
	}
	return diff, nil
}

func getRulesDiff(oldRules, newRules []Rule) []RuleDiff {
	var (
		ruleDiff      []RuleDiff
		addedChecks   = getCheckDifference(newRules, oldRules)
		removedChecks = getCheckDifference(oldRules, newRules)
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
