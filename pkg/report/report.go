// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"time"

	"k8s.io/component-base/version"

	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
)

// Report contains information about a Diki run
// in a suitable for reporting format.
type Report struct {
	Time        time.Time      `json:"time"`
	MinStatus   rule.Status    `json:"minStatus,omitempty"`
	DikiVersion string         `json:"dikiVersion"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	Providers   []Provider     `json:"providers"`
}

// Provider contains information about a known provider
// and its ran rulesets.
type Provider struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Rulesets []Ruleset         `json:"rulesets"`
}

// Ruleset contains information about a rule set and its rules.
type Ruleset struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

// Rule contains information about a ran rule.
type Rule struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Checks []Check `json:"checks"`
}

// Check is the result of a single Rule check.
type Check struct {
	Status  rule.Status   `json:"status"`
	Message string        `json:"message"`
	Targets []rule.Target `json:"targets,omitempty"`
}

// ReportOptions are options that can be applied to a Report.
type ReportOptions struct {
	MinStatus rule.Status
	Metadata  map[string]any
}

// ReportOption defines a single option that can be applied to a Report.
type ReportOption interface {
	ApplyToReport(*ReportOptions)
}

// MinStatus is the minimal reporting status.
type MinStatus rule.Status

// ApplyToReport implements ReportOption.
func (ms MinStatus) ApplyToReport(opts *ReportOptions) {
	if slices.Contains(rule.Statuses(), rule.Status(ms)) {
		opts.MinStatus = rule.Status(ms)
	}
}

// Metadata is additional report values.
type Metadata map[string]any

// ApplyToReport implements ReportOption.
func (md Metadata) ApplyToReport(opts *ReportOptions) {
	opts.Metadata = maps.Clone(md)
}

// FromProviderResults returns a Diki report from ProviderResults.
func FromProviderResults(results []provider.ProviderResult, options ...ReportOption) *Report {
	opts := &ReportOptions{}
	for _, o := range options {
		o.ApplyToReport(opts)
	}
	report := &Report{
		Time:        time.Now().UTC(),
		MinStatus:   opts.MinStatus,
		DikiVersion: version.Get().GitVersion,
		Metadata:    opts.Metadata,
		Providers:   make([]Provider, 0, len(results)),
	}
	for _, providerResult := range results {
		p := Provider{
			ID:       providerResult.ProviderID,
			Name:     providerResult.ProviderName,
			Metadata: providerResult.Metadata,
			Rulesets: getRulesets(providerResult.RulesetResults, opts),
		}
		report.Providers = append(report.Providers, p)
	}
	return report
}

// WriteToFile writes a Diki report to a file.
func (r *Report) WriteToFile(filePath string) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0600)
}

// rulesetSummaryText returns a summary string with the number of rules with results per status.
func rulesetSummaryText(ruleset *Ruleset) string {
	statuses := rule.Statuses()
	summaryText := ""
	for _, status := range statuses {
		num := numOfRulesWithStatus(ruleset, status)
		if num != 0 {
			if len(summaryText) > 0 {
				summaryText = fmt.Sprintf("%s, ", summaryText)
			}
			summaryText = fmt.Sprintf("%s%dx %s %c", summaryText, num, status, rule.StatusIcon(status))
		}
	}
	return summaryText
}

func numOfRulesWithStatus(ruleset *Ruleset, status rule.Status) int {
	num := 0
	for _, rule := range ruleset.Rules {
		for _, check := range rule.Checks {
			if check.Status == status {
				num++
				break
			}
		}
	}
	return num
}

// rulesWithStatus return all rules that have results with a given status.
func rulesWithStatus(ruleset *Ruleset, status rule.Status) []Rule {
	result := []Rule{}
	for _, rule := range ruleset.Rules {
		ruleWithStatus := Rule{ID: rule.ID, Name: rule.Name}
		for _, check := range rule.Checks {
			if check.Status == status {
				ruleWithStatus.Checks = append(ruleWithStatus.Checks, check)
			}
		}
		if len(ruleWithStatus.Checks) > 0 {
			result = append(result, ruleWithStatus)
		}
	}
	// sort rules by id
	slices.SortFunc(result, func(a, b Rule) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return result
}

func getRulesets(rulesetResults []ruleset.RulesetResult, opts *ReportOptions) []Ruleset {
	rulesets := make([]Ruleset, 0, len(rulesetResults))
	for _, rulesetResult := range rulesetResults {
		rs := Ruleset{
			ID:      rulesetResult.RulesetID,
			Name:    rulesetResult.RulesetName,
			Version: rulesetResult.RulesetVersion,
			Rules:   getRules(rulesetResult.RuleResults, opts),
		}
		rulesets = append(rulesets, rs)
	}
	return rulesets
}

func getRules(ruleResults []rule.RuleResult, opts *ReportOptions) []Rule {
	rules := make([]Rule, 0, len(ruleResults))
	for _, ruleResult := range ruleResults {
		r := Rule{
			ID:     ruleResult.RuleID,
			Name:   ruleResult.RuleName,
			Checks: getChecks(ruleResult.CheckResults, opts),
		}
		rules = append(rules, r)
	}
	return rules
}

func getChecks(checkResults []rule.CheckResult, opts *ReportOptions) []Check {
	groupedChecks := map[string]*Check{}
	for _, checkResult := range checkResults {
		if opts.MinStatus != "" && checkResult.Status.Less(opts.MinStatus) {
			continue
		}
		key := fmt.Sprintf("%s--%s", checkResult.Status, checkResult.Message)
		check, ok := groupedChecks[key]
		if !ok {
			check := &Check{
				Status:  checkResult.Status,
				Message: checkResult.Message,
				Targets: []rule.Target{},
			}

			if checkResult.Target != nil {
				check.Targets = append(check.Targets, checkResult.Target)
			}
			groupedChecks[key] = check
		} else if checkResult.Target != nil {
			check.Targets = append(check.Targets, checkResult.Target)
		}
	}

	checks := make([]Check, 0, len(groupedChecks))
	for _, check := range groupedChecks {
		checks = append(checks, *check)
	}
	return checks
}

func sortedKeys[T any](m map[string]T) []string {
	res := make([]string, 0, len(m))
	for k := range m {
		res = append(res, k)
	}
	slices.Sort(res)
	return res
}
