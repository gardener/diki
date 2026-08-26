// SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package junitreportparser

import (
	"encoding/xml"
	"fmt"
	"maps"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
)

// ParseXMLReport parses a JUnit-style XML report emitted by the gardenlinux/tests Pod and converts it into a ruleset.RulesetResult.
func ParseXMLReport(xmlContent string, node *corev1.Node) (ruleset.RulesetResult, error) {
	var testSuites junitTestSuites
	if err := xml.NewDecoder(strings.NewReader(xmlContent)).Decode(&testSuites); err != nil {
		return ruleset.RulesetResult{}, err
	}

	// We expect for the report to contain only one testsuite.
	if len(testSuites.Suites) != 1 {
		return ruleset.RulesetResult{}, fmt.Errorf("expected to receive 1 report suite, received %d instead", len(testSuites.Suites))
	}

	var (
		nodeTarget = kubeutils.TargetWithK8sObject(rule.NewTarget(), metav1.TypeMeta{Kind: "Node"}, node.ObjectMeta).With("osImage", node.Status.NodeInfo.OSImage)
		result     = ruleset.RulesetResult{
			RuleResults: []rule.RuleResult{},
		}
		ruleIndex = map[string]int{}
	)

	for _, testcase := range testSuites.Suites[0].TestCases {
		props, err := parseProperties(testcase)
		if err != nil {
			return ruleset.RulesetResult{}, fmt.Errorf("failed to parse properties of testcase %q: %w", testcase.ClassName, err)
		}

		ruleName, checkDescription := splitDocstring(props.docstring)
		if ruleName == nil {
			ruleName = &testcase.ClassName
		}

		status, statusMessage := statusFor(testcase)
		check := rule.CheckResult{
			Status:  status,
			Message: composeCheckMessage(checkDescription, statusMessage),
			Target:  nodeTarget,
		}

		if idx, ok := ruleIndex[props.securityID]; ok {
			// A single report may contain multiple testcases sharing the same security_id
			// that render to an identical check result. Deduplicate them so a rule does not
			// accumulate redundant checks (and, downstream, duplicated node targets).
			if !containsCheckResult(result.RuleResults[idx].CheckResults, check) {
				result.RuleResults[idx].CheckResults = append(result.RuleResults[idx].CheckResults, check)
			}
			continue
		}

		ruleIndex[props.securityID] = len(result.RuleResults)
		result.RuleResults = append(result.RuleResults, rule.RuleResult{
			RuleID:       props.securityID,
			RuleName:     *ruleName,
			CheckResults: []rule.CheckResult{check},
		})
	}

	return result, nil
}

// testcaseProperties holds the recognized <property> values of a testcase.
type testcaseProperties struct {
	securityID string
	docstring  string
}

func parseProperties(tc junitTestCase) (testcaseProperties, error) {
	if tc.Properties == nil {
		return testcaseProperties{}, fmt.Errorf("testcase has no properties")
	}

	var props testcaseProperties
	for _, p := range tc.Properties.Properties {
		switch p.Name {
		case securityIDKey:
			props.securityID = strings.TrimSpace(p.Value)
		case docstringKey:
			props.docstring = strings.TrimSpace(p.Value)
		}
	}

	// The way we run the gardenlinux tests makes it mandatory for all testcases present in the report to have a security_id property
	if len(props.securityID) == 0 {
		return testcaseProperties{}, fmt.Errorf("testcase with classname %s and name %s has an empty %s property", tc.ClassName, tc.Name, securityIDKey)
	}

	return props, nil
}

func statusFor(tc junitTestCase) (rule.Status, *string) {
	switch {
	case tc.Failure != nil:
		// TODO (georgibaltiev): Currently, there is an issue with some Failure tests containing verbose messages containing STDOUT logs. This truncation will be removed once the issues have been resolved.
		return rule.Failed, firstLine(tc.Failure.Message)
	case tc.Error != nil:
		return rule.Errored, &tc.Error.Message
	case tc.Skipped != nil:
		return rule.Skipped, &tc.Skipped.Message
	default:
		return rule.Passed, nil
	}
}

// TODO (georgibaltiev): Remove this truncation once the failure testcase messages in the XML report are appropriately displayed.
// Currently, some failure testcases dump the entire STDOUT from the assertions.
func firstLine(s string) *string {
	line, _, _ := strings.Cut(s, "\n")
	return &line
}

func splitDocstring(docstring string) (ruleName, checkDescription *string) {
	docstring = strings.TrimSpace(docstring)
	paragraphs := splitParagraphsByNewlines(docstring)

	// The docstring on each testcase is formatted in the following way:
	// <Reference to the ID> \n\n <Name of the rule, mapped to the ID> \n\n <Description of the check, which is being performed (could be more than one per rule)>
	// The check description is optional, so a docstring may consist of only the reference and the rule name.
	// We only require the name and, when present, the description of the check.
	switch len(paragraphs) {
	case 2:
		return paragraphs[1], nil
	case 3:
		return paragraphs[1], paragraphs[2]
	default:
		return nil, nil
	}
}

func splitParagraphsByNewlines(s string) []*string {
	raw := strings.Split(s, "\n\n")
	out := make([]*string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, &p)
		}
	}
	return out
}

func composeCheckMessage(checkDescription, statusMessage *string) string {
	parts := make([]string, 0, 3)

	if checkDescription != nil {
		parts = append(parts, *checkDescription)
	}

	if statusMessage != nil {
		parts = append(parts, *statusMessage)
	}

	return strings.Join(parts, " - ")
}

// containsCheckResult reports whether checks already holds a check result equal to target.
func containsCheckResult(checks []rule.CheckResult, target rule.CheckResult) bool {
	for _, c := range checks {
		if c.Status == target.Status && c.Message == target.Message && maps.Equal(c.Target, target.Target) {
			return true
		}
	}
	return false
}

// MergeRulesetResults collapses multiple RulesetResults (typically one per node)
// into a single result. Rules are keyed by RuleID: CheckResults from every input
// are appended to the corresponding rule entry. Rule ordering follows first
// appearance across all inputs, and the ruleset metadata (ID/name/version) is
// taken from results[0].
func MergeRulesetResults(rulesetResults []ruleset.RulesetResult) ruleset.RulesetResult {
	if len(rulesetResults) == 0 {
		return ruleset.RulesetResult{}
	}
	if len(rulesetResults) == 1 {
		return rulesetResults[0]
	}

	base := rulesetResults[0]
	mergedResults := ruleset.RulesetResult{
		RulesetID:      base.RulesetID,
		RulesetName:    base.RulesetName,
		RulesetVersion: base.RulesetVersion,
		RuleResults:    []rule.RuleResult{},
	}

	ruleIndex := map[string]int{}
	for _, res := range rulesetResults {
		for _, rr := range res.RuleResults {
			if idx, ok := ruleIndex[rr.RuleID]; ok {
				mergedResults.RuleResults[idx].CheckResults = append(mergedResults.RuleResults[idx].CheckResults, rr.CheckResults...)
				continue
			}
			ruleIndex[rr.RuleID] = len(mergedResults.RuleResults)
			mergedResults.RuleResults = append(mergedResults.RuleResults, rule.RuleResult{
				RuleID:       rr.RuleID,
				RuleName:     rr.RuleName,
				CheckResults: append([]rule.CheckResult(nil), rr.CheckResults...),
			})
		}
	}

	return mergedResults
}
