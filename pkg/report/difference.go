// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gardener/diki/pkg/rule"
)

// DifferenceReportsWrapper wraps DifferenceReports and additional attributes needed for html rendering.
type DifferenceReportsWrapper struct {
	DifferenceReports  []*DifferenceReport `json:"differenceReports"`
	IdentityAttributes map[string]string   `json:"identityAttributes"`
}

// DifferenceReport contains the difference between two reports.
type DifferenceReport struct {
	Title     string               `json:"title,omitempty"`
	Time      time.Time            `json:"time"`
	MinStatus rule.Status          `json:"minStatus,omitempty"`
	Providers []ProviderDifference `json:"providers"`
}

// ProviderDifference contains the difference between two reports
// for a known provider and its ran rulesets.
type ProviderDifference struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	OldMetadata map[string]string   `json:"oldMetadata,omitempty"`
	NewMetadata map[string]string   `json:"newMetadata,omitempty"`
	Rulesets    []RulesetDifference `json:"rulesets"`
}

// RulesetDifference contains the difference between two reports
// for a ruleset and its rules.
type RulesetDifference struct {
	ID      string           `json:"id"`
	Name    string           `json:"name"`
	Version string           `json:"version"`
	Rules   []RuleDifference `json:"rules"`
}

// RuleDifference contains the difference between two reports for a single rule.
type RuleDifference struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Added   []Check `json:"added,omitempty"`
	Removed []Check `json:"removed,omitempty"`
}

// CreateDifference creates the difference between two reports.
func CreateDifference(oldReport Report, newReport Report, title string) (*DifferenceReport, error) {
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

	diff := &DifferenceReport{
		Title:     title,
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
// provider IDs contained in providers1 and providers2.
func getUniqueProviders(providers1, providers2 []Provider) []string {
	var providers []string
	for _, p1 := range providers1 {
		providers = append(providers, p1.ID)
	}

	for _, p2 := range providers2 {
		p1Idx := slices.IndexFunc(providers1, func(p1 Provider) bool {
			return p2.ID == p1.ID
		})

		if p1Idx < 0 {
			providers = append(providers, p2.ID)
		}
	}
	return providers
}

// getUniqueRulesets returns a map of all unique rulesets,
// where the maps keys are ruleset IDs and the values are a
// list of all unique versions in rulests1 and rulests2.
func getUniqueRulesets(rulesets1, rulesets2 []Ruleset) map[string][]string {
	rulesets := map[string][]string{}
	for _, rs1 := range rulesets1 {
		rulesets[rs1.ID] = append(rulesets[rs1.ID], rs1.Version)
	}

	for _, rs2 := range rulesets2 {
		rs1Idx := slices.IndexFunc(rulesets1, func(rs1 Ruleset) bool {
			return rs2.ID == rs1.ID && rs2.Version == rs1.Version
		})

		if rs1Idx < 0 {
			rulesets[rs2.ID] = append(rulesets[rs2.ID], rs2.Version)
		}
	}
	return rulesets
}

// rulesetDiffAddedSummaryText returns a summary string with the number of added status types.
func rulesetDiffAddedSummaryText(ruleset *RulesetDifference) string {
	var added = map[rule.Status]int{}
	for _, rule := range ruleset.Rules {
		for _, check := range rule.Added {
			added[check.Status]++
		}
	}
	return rulesetDiffSummaryText(added)
}

// rulesetDiffRemovedSummaryText returns a summary string with the number of removed status types.
func rulesetDiffRemovedSummaryText(ruleset *RulesetDifference) string {
	var removed = map[rule.Status]int{}
	for _, rule := range ruleset.Rules {
		for _, check := range rule.Removed {
			removed[check.Status]++
		}
	}
	return rulesetDiffSummaryText(removed)
}

func rulesetDiffSummaryText(statusesCount map[rule.Status]int) string {
	var (
		summaryBuilder strings.Builder
		statuses       = rule.Statuses()
	)
	for _, status := range statuses {
		if val, ok := statusesCount[status]; ok {
			if summaryBuilder.Len() > 0 {
				summaryBuilder.WriteString(", ")
			}
			summaryBuilder.WriteString(fmt.Sprintf("%dx %s %c", val, status, rule.GetStatusIcon(status)))
		}
	}
	if summaryBuilder.Len() == 0 {
		return "None"
	}
	return summaryBuilder.String()
}

func getProviderDiffIDText(providerDiff ProviderDifference, key string) string {
	switch {
	case len(providerDiff.OldMetadata[key]) == 0 && len(providerDiff.NewMetadata[key]) == 0:
		return ""
	case providerDiff.OldMetadata[key] == providerDiff.NewMetadata[key]:
		return fmt.Sprintf("- %s", providerDiff.NewMetadata[key])
	default:
		return fmt.Sprintf("- %s/%s", providerDiff.OldMetadata[key], providerDiff.NewMetadata[key])
	}
}
