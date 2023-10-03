// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gardener/diki/pkg/rule"
)

// MergedReport contains information about multiple Diki
// runs in a suitable for reporting format.
type MergedReport struct {
	Time      time.Time        `json:"time"`
	MinStatus rule.Status      `json:"minStatus,omitempty"`
	Providers []MergedProvider `json:"providers"`
}

// MergedProvider contains information from multiple reports about
// a known provider and its ran rulesets.
type MergedProvider struct {
	ID         string                       `json:"id"`
	Name       string                       `json:"name"`
	DistinctBy string                       `json:"distinctBy"`
	Metadata   map[string]map[string]string `json:"metadata,omitempty"`
	Rulesets   []MergedRuleset              `json:"rulesets"`
}

// mergeRulesets traverses the rulesets from a single report
// and merges them into the already existing ones.
func (mp *MergedProvider) mergeRulesets(uniqueAttrVal string, rulesets []Ruleset) {
	for _, ruleset := range rulesets {
		idx := slices.IndexFunc(mp.Rulesets, func(mr MergedRuleset) bool {
			return ruleset.ID == mr.ID && ruleset.Version == mr.Version
		})

		if idx >= 0 {
			mp.Rulesets[idx].mergeRules(uniqueAttrVal, ruleset.Rules)
		} else {
			mergedRuleset := MergedRuleset{
				ID:      ruleset.ID,
				Name:    ruleset.Name,
				Version: ruleset.Version,
				Rules:   []MergedRule{},
			}
			mergedRuleset.mergeRules(uniqueAttrVal, ruleset.Rules)
			mp.Rulesets = append(mp.Rulesets, mergedRuleset)
		}
	}
}

// MergedRuleset contains information from multiple reports about a ruleset and its rules.
type MergedRuleset struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Version string       `json:"version"`
	Rules   []MergedRule `json:"rules"`
}

// mergeRules traverses the rules from a single ruleset
// and merges them into the already existing ones.
func (mr *MergedRuleset) mergeRules(uniqueAttrVal string, rules []Rule) {
	for _, rule := range rules {
		idx := slices.IndexFunc(mr.Rules, func(mr MergedRule) bool {
			return rule.ID == mr.ID
		})

		if idx >= 0 {
			mr.Rules[idx].mergeChecks(uniqueAttrVal, rule.Checks)
		} else {
			mergedRule := MergedRule{
				ID:     rule.ID,
				Name:   rule.Name,
				Checks: []MergedCheck{},
			}
			mergedRule.mergeChecks(uniqueAttrVal, rule.Checks)
			mr.Rules = append(mr.Rules, mergedRule)
		}
	}
}

// MergedRule contains information about a ran rule for multiple reports.
type MergedRule struct {
	ID     string        `json:"id"`
	Name   string        `json:"name"`
	Checks []MergedCheck `json:"checks"`
}

// mergeChecks traverses the checks from a single rule
// and merges them into the already existing ones.
func (mr *MergedRule) mergeChecks(uniqueAttrVal string, checks []Check) {
	for _, check := range checks {
		idx := slices.IndexFunc(mr.Checks, func(mr MergedCheck) bool {
			return check.Message == mr.Message && check.Status == mr.Status
		})

		if idx >= 0 {
			mr.Checks[idx].ReportsTargets[uniqueAttrVal] = check.Targets
		} else {
			mergedCheck := MergedCheck{
				Message:        check.Message,
				Status:         check.Status,
				ReportsTargets: map[string][]rule.Target{},
			}
			mergedCheck.ReportsTargets[uniqueAttrVal] = check.Targets
			mr.Checks = append(mr.Checks, mergedCheck)
		}
	}
}

// MergedCheck is the result of a single Rule check for multiple reports.
type MergedCheck struct {
	Status         rule.Status              `json:"status"`
	Message        string                   `json:"message"`
	ReportsTargets map[string][]rule.Target `json:"targets,omitempty"`
}

// MergeReport merges given reports by specified providers and unique metadata attribute.
func MergeReport(reports []*Report, distinctByAttrs map[string]string) (*MergedReport, error) {
	if len(reports) == 0 {
		return nil, errors.New("zero reports provided for merging")
	}
	mergedReport := &MergedReport{
		Time:      time.Now(),
		MinStatus: reports[0].MinStatus,
		Providers: []MergedProvider{},
	}

	distinctByAttrsProviders := []string{}
	for key := range distinctByAttrs {
		distinctByAttrsProviders = append(distinctByAttrsProviders, key)
	}
	slices.Sort(distinctByAttrsProviders)

	for _, selectedProvider := range distinctByAttrsProviders {
		mergedReport.Providers = append(mergedReport.Providers, MergedProvider{
			ID:         selectedProvider,
			Name:       "",
			DistinctBy: distinctByAttrs[selectedProvider],
			Metadata:   map[string]map[string]string{},
			Rulesets:   []MergedRuleset{},
		})
	}

	for _, report := range reports {
		if report.MinStatus != mergedReport.MinStatus {
			return nil, errors.New("reports must have equal minStatus in order to be merged")
		}

		for key, mergedProvider := range mergedReport.Providers {
			idx := slices.IndexFunc(report.Providers, func(p Provider) bool {
				return p.ID == mergedProvider.ID
			})

			if idx == -1 {
				return nil, fmt.Errorf("provider %s not found in at least 1 of the selected reports", mergedProvider.ID)
			}

			if mergedReport.Providers[key].Name == "" {
				mergedReport.Providers[key].Name = report.Providers[idx].Name
			}

			uniqueAttr := report.Providers[idx].Metadata[mergedProvider.DistinctBy]
			if uniqueAttr == "" {
				return nil, fmt.Errorf("distinct attribute %s is empty in at least 1 of the selected reports", mergedProvider.DistinctBy)
			}

			if _, ok := mergedProvider.Metadata[uniqueAttr]; ok {
				return nil, fmt.Errorf("distinct attribute %s is not unique", mergedProvider.DistinctBy)
			}

			mergedProvider.Metadata[uniqueAttr] = report.Providers[idx].Metadata
			mergedProvider.Metadata[uniqueAttr]["time"] = report.Time.Format("01-02-2006 15:04:05")
		}
	}
	for _, report := range reports {
		for idx, mergedProvider := range mergedReport.Providers {
			for _, provider := range report.Providers {
				if provider.ID == mergedProvider.ID {
					uniqueAttr := provider.Metadata[mergedProvider.DistinctBy]
					mergedProvider.mergeRulesets(uniqueAttr, provider.Rulesets)
					mergedReport.Providers[idx] = mergedProvider
				}
			}
		}
	}
	return mergedReport, nil
}

// rulesWithStatus return all rules that have results with a given status.
func mergedRulesWithStatus(ruleset *MergedRuleset, status rule.Status) []MergedRule {
	result := []MergedRule{}
	for _, rule := range ruleset.Rules {
		ruleWithStatus := MergedRule{ID: rule.ID, Name: rule.Name}
		for _, check := range rule.Checks {
			if check.Status == status {
				ruleWithStatus.Checks = append(ruleWithStatus.Checks, check)
			}
		}
		if len(ruleWithStatus.Checks) > 0 {
			result = append(result, ruleWithStatus)
		}
	}
	return result
}

// mergedRulesetSummaryText returns a summary string with the number of merged rules with results per status.
func mergedRulesetSummaryText(ruleset *MergedRuleset) string {
	statuses := rule.Statuses()
	summaryText := ""
	for _, status := range statuses {
		num := numOfMergedRulesWithStatus(ruleset, status)
		if num != 0 {
			if len(summaryText) > 0 {
				summaryText = fmt.Sprintf("%s, ", summaryText)
			}
			summaryText = fmt.Sprintf("%s%dx %s %c", summaryText, num, status, rule.GetStatusIcon(status))
		}
	}
	return summaryText
}

func numOfMergedRulesWithStatus(ruleset *MergedRuleset, status rule.Status) int {
	num := 0
	for _, rule := range ruleset.Rules {
		if hasStatus := slices.ContainsFunc(rule.Checks, func(check MergedCheck) bool {
			return check.Status == status
		}); hasStatus {
			num++
		}
	}
	return num
}

func metadataTextForMergedProvider(mp MergedProvider) map[string]string {
	metadataTexts := make(map[string]string, len(mp.Metadata))
	for id, metadata := range mp.Metadata {
		var sb strings.Builder
		empty := true
		keys := sortedKeys(metadata)
		for _, key := range keys {
			if key == mp.DistinctBy {
				continue
			}
			if empty {
				sb.WriteString("(")
				empty = false
			}
			sb.WriteString(fmt.Sprintf("%s: %s, ", key, metadata[key]))
		}

		metadataText := sb.String()
		if !empty {
			metadataText = metadataText[:len(metadataText)-2]
			metadataText += ")"
		}
		metadataTexts[id] = metadataText
	}
	return metadataTexts
}
