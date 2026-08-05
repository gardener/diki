// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/xml"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
)

type junitTestProperty struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

type junitPropertyElement struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitProperties struct {
	Properties []junitPropertyElement `xml:"property"`
}

type junitTestCase struct {
	ClassName  string             `xml:"classname,attr"`
	Name       string             `xml:"name,attr"`
	Failure    *junitTestProperty `xml:"failure"`
	Error      *junitTestProperty `xml:"error"`
	Skipped    *junitTestProperty `xml:"skipped"`
	Properties *junitProperties   `xml:"properties"`
}

type junitTestSuite struct {
	Name      string          `xml:"name,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestSuites struct {
	Name   string           `xml:"name,attr"`
	Suites []junitTestSuite `xml:"testsuite"`
}

// ParseXMLReport parses a JUnit-style XML report emitted by the gardenlinux/tests Pod and converts it into a ruleset.RulesetResult.
func ParseXMLReport(xmlContent string, nodeMeta metav1.ObjectMeta) (ruleset.RulesetResult, error) {
	var testSuites junitTestSuites
	if err := xml.NewDecoder(strings.NewReader(xmlContent)).Decode(&testSuites); err != nil {
		return ruleset.RulesetResult{}, err
	}

	if len(testSuites.Suites) == 0 && testSuites.Name == "" {
		return ruleset.RulesetResult{}, nil
	}

	nodeTarget := kubeutils.TargetWithK8sObject(rule.Target{}, metav1.TypeMeta{Kind: "Node"}, nodeMeta)
	result := ruleset.RulesetResult{
		RuleResults: []rule.RuleResult{},
	}
	ruleIndex := map[string]int{}

	for _, suite := range testSuites.Suites {
		for _, testcase := range suite.TestCases {
			props := parseProperties(testcase)
			if props.disaStigVersion != "" && props.disaStigVersion != "None" {
				result.RulesetVersion = props.disaStigVersion
			}

			ruleName, checkDescription := splitDocstring(props.docstring)
			if ruleName == "" {
				ruleName = testcase.ClassName
			}

			status, statusMessage := statusFor(testcase)
			check := rule.CheckResult{
				Status:  status,
				Message: composeCheckMessage(checkDescription, statusMessage, testcase.Name),
				Target:  nodeTarget,
			}

			if idx, ok := ruleIndex[props.securityID]; ok {
				result.RuleResults[idx].CheckResults = append(result.RuleResults[idx].CheckResults, check)
				continue
			}

			ruleIndex[props.securityID] = len(result.RuleResults)
			result.RuleResults = append(result.RuleResults, rule.RuleResult{
				RuleID:       props.securityID,
				RuleName:     ruleName,
				CheckResults: []rule.CheckResult{check},
			})
		}
	}

	return result, nil
}

// testcaseProperties holds the recognized <property> values of a testcase.
type testcaseProperties struct {
	securityID      string
	docstring       string
	disaStigVersion string
}

func parseProperties(tc junitTestCase) testcaseProperties {
	var props testcaseProperties
	if tc.Properties == nil {
		return props
	}
	for _, p := range tc.Properties.Properties {
		switch p.Name {
		case "security_id":
			props.securityID = strings.TrimSpace(p.Value)
		case "docstring":
			props.docstring = strings.TrimSpace(p.Value)
		case "disa_stig_version":
			props.disaStigVersion = strings.TrimSpace(p.Value)
		}
	}
	return props
}

func statusFor(tc junitTestCase) (rule.Status, string) {
	switch {
	case tc.Failure != nil:
		// TODO (georgibaltiev): Remove this truncation in the near future
		return rule.Failed, firstLine(tc.Failure.Message)
	case tc.Error != nil:
		return rule.Errored, tc.Error.Message
	case tc.Skipped != nil:
		return rule.Skipped, tc.Skipped.Message
	default:
		return rule.Passed, ""
	}
}

// TODO (georgibaltiev): Remove this truncation once the failure testcase messages in the XML report are appropriately displayed.
// Currently, some failure testcases dump the entire STDOUT from the assertions.
func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func splitDocstring(docstring string) (ruleName, checkDescription string) {
	docstring = strings.TrimSpace(docstring)
	if docstring == "" {
		return "", ""
	}

	paragraphs := splitParagraphs(docstring)
	if len(paragraphs) > 0 {
		paragraphs = paragraphs[1:]
	}

	switch len(paragraphs) {
	case 0:
		return "", ""
	case 1:
		return paragraphs[0], ""
	default:
		return paragraphs[0], paragraphs[len(paragraphs)-1]
	}
}

func splitParagraphs(s string) []string {
	raw := strings.Split(s, "\n\n")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func composeCheckMessage(checkDescription, statusMessage, testName string) string {
	parts := make([]string, 0, 3)
	if checkDescription != "" {
		parts = append(parts, checkDescription)
	} else if testName != "" {
		parts = append(parts, testName)
	}
	if statusMessage != "" {
		parts = append(parts, statusMessage)
	}
	return strings.Join(parts, " — ")
}

// MergeRulesetResults collapses multiple RulesetResults (typically one per node)
// into a single result. Rules are keyed by RuleID: CheckResults from every input
// are appended to the corresponding rule entry. Rule ordering follows first
// appearance across all inputs, and the ruleset metadata (ID/name/version) is
// taken from results[0].
func MergeRulesetResults(results []ruleset.RulesetResult) ruleset.RulesetResult {
	if len(results) == 0 {
		return ruleset.RulesetResult{}
	}
	if len(results) == 1 {
		return results[0]
	}

	base := results[0]
	out := ruleset.RulesetResult{
		RulesetID:      base.RulesetID,
		RulesetName:    base.RulesetName,
		RulesetVersion: base.RulesetVersion,
		RuleResults:    []rule.RuleResult{},
	}

	ruleIndex := map[string]int{}
	for _, res := range results {
		for _, rr := range res.RuleResults {
			if idx, ok := ruleIndex[rr.RuleID]; ok {
				out.RuleResults[idx].CheckResults = append(out.RuleResults[idx].CheckResults, rr.CheckResults...)
				continue
			}
			ruleIndex[rr.RuleID] = len(out.RuleResults)
			out.RuleResults = append(out.RuleResults, rule.RuleResult{
				RuleID:       rr.RuleID,
				RuleName:     rr.RuleName,
				CheckResults: append([]rule.CheckResult(nil), rr.CheckResults...),
			})
		}
	}

	return out
}
