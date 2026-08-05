// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package parser_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/gardenlinux/parser"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
)

var _ = Describe("ParseXMLReport", func() {
	const nodeName = "node-1"

	nodeMeta := metav1.ObjectMeta{Name: nodeName}

	// testcaseXML wraps a single <testcase> body in the enclosing testsuites/testsuite elements.
	testcaseXML := func(inner string) string {
		return `<testsuites name="root"><testsuite name="s"><testcase name="tc" classname="C">` +
			inner + `</testcase></testsuite></testsuites>`
	}

	DescribeTable("should reject or ignore reports that yield no rules",
		func(xml string, expectErr bool, expected ruleset.RulesetResult) {
			result, err := parser.ParseXMLReport(xml, nodeMeta)

			if expectErr {
				Expect(err).To(HaveOccurred())
				return
			}
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal(expected))
		},
		Entry("empty testsuites", `<testsuites></testsuites>`, false, ruleset.RulesetResult{}),
		Entry("malformed XML", `<testsuites><testsuite>`, true, ruleset.RulesetResult{}),
	)

	DescribeTable("should map a single testcase to the expected status and message",
		func(inner string, expectedStatus rule.Status, expectedMessage string) {
			result, err := parser.ParseXMLReport(testcaseXML(inner), nodeMeta)

			Expect(err).ToNot(HaveOccurred())
			Expect(result.RuleResults[0].CheckResults[0]).To(Equal(rule.CheckResult{
				Status:  expectedStatus,
				Message: expectedMessage,
				Target:  rule.NewTarget("kind", "Node", "name", nodeName),
			}))
		},
		Entry("passing testcase", ``, rule.Passed, "tc"),
		Entry("failure with message attr", `<failure message="fail"></failure>`, rule.Failed, "tc — fail"),
		Entry("error with message attr", `<error message="err"></error>`, rule.Errored, "tc — err"),
		Entry("skipped with message attr", `<skipped message="not applicable"></skipped>`, rule.Skipped, "tc — not applicable"),
	)

	It("should truncate a failure message to its first line", func() {
		xml := testcaseXML(`<failure message="assertion failed&#10;full captured output&#10;more noise"></failure>`)

		result, err := parser.ParseXMLReport(xml, nodeMeta)

		Expect(err).ToNot(HaveOccurred())
		Expect(result.RuleResults[0].CheckResults[0].Message).To(Equal("tc — assertion failed"))
	})

	DescribeTable("should derive rule and check metadata from a single testcase",
		func(inner string, assertFunc func(rule.RuleResult)) {
			result, err := parser.ParseXMLReport(testcaseXML(inner), nodeMeta)

			Expect(err).ToNot(HaveOccurred())
			Expect(result.RuleResults).To(HaveLen(1))
			assertFunc(result.RuleResults[0])
		},
		Entry("sets the node on the check target", ``, func(rr rule.RuleResult) {
			Expect(rr.CheckResults[0].Target).To(Equal(rule.NewTarget("kind", "Node", "name", nodeName)))
		}),
		Entry("uses the security_id property as the RuleID",
			`<properties><property name="security_id" value="SEC-42"/></properties>`,
			func(rr rule.RuleResult) {
				Expect(rr.RuleID).To(Equal("SEC-42"))
			}),
		Entry("derives the RuleName from the first docstring paragraph and drops a Ref prefix",
			`<properties><property name="docstring" value="Ref: Ref-1&#10;&#10;My Rule Name&#10;&#10;Check detail"/></properties>`,
			func(rr rule.RuleResult) {
				Expect(rr).To(Equal(rule.RuleResult{
					RuleName: "My Rule Name",
					CheckResults: []rule.CheckResult{
						{Status: rule.Passed, Message: "Check detail", Target: rule.NewTarget("kind", "Node", "name", nodeName)},
					},
				}))
			}),
		Entry("falls back to the classname when the docstring yields no rule name", ``, func(rr rule.RuleResult) {
			Expect(rr.RuleName).To(Equal("C"))
		}),
		Entry("prefers the failure message attribute over the chardata text",
			`<failure message="attr">chardata</failure>`,
			func(rr rule.RuleResult) {
				Expect(rr.CheckResults[0].Message).To(Equal("tc — attr"))
			}),
	)

	DescribeTable("should record the disa_stig_version as the ruleset version",
		func(inner string, expectedVersion string) {
			result, err := parser.ParseXMLReport(testcaseXML(inner), nodeMeta)

			Expect(err).ToNot(HaveOccurred())
			Expect(result.RulesetVersion).To(Equal(expectedVersion))
		},
		Entry("stores a concrete version",
			`<properties><property name="disa_stig_version" value="1.2.3"/></properties>`,
			"1.2.3"),
		Entry("omits the None placeholder",
			`<properties><property name="disa_stig_version" value="None"/></properties>`,
			""),
		Entry("omits an absent version", ``, ""),
	)

	It("should fall back to the test name in the message when there is no check description", func() {
		xml := `<testsuites name="root"><testsuite name="s">
			<testcase name="my-test-name" classname="C"></testcase>
		</testsuite></testsuites>`

		result, err := parser.ParseXMLReport(xml, nodeMeta)

		Expect(err).ToNot(HaveOccurred())
		Expect(result.RuleResults[0].CheckResults[0].Message).To(Equal("my-test-name"))
	})

	It("should group testcases sharing the same security_id into one rule", func() {
		xml := `<testsuites name="root"><testsuite name="s">
			<testcase name="a" classname="C">
				<properties><property name="security_id" value="SEC-1"/></properties>
			</testcase>
			<testcase name="b" classname="C"><failure message="bad"></failure>
				<properties><property name="security_id" value="SEC-1"/></properties>
			</testcase>
		</testsuite></testsuites>`

		result, err := parser.ParseXMLReport(xml, nodeMeta)

		Expect(err).ToNot(HaveOccurred())
		Expect(result.RuleResults).To(Equal([]rule.RuleResult{
			{
				RuleID:   "SEC-1",
				RuleName: "C",
				CheckResults: []rule.CheckResult{
					{Status: rule.Passed, Message: "a", Target: rule.NewTarget("kind", "Node", "name", nodeName)},
					{Status: rule.Failed, Message: "b — bad", Target: rule.NewTarget("kind", "Node", "name", nodeName)},
				},
			},
		}))
	})

	It("should preserve rule ordering across multiple suites", func() {
		xml := `<testsuites name="root">
			<testsuite name="s1"><testcase name="a" classname="C">
				<properties><property name="security_id" value="SEC-A"/></properties>
			</testcase></testsuite>
			<testsuite name="s2"><testcase name="b" classname="C">
				<properties><property name="security_id" value="SEC-B"/></properties>
			</testcase></testsuite>
		</testsuites>`

		result, err := parser.ParseXMLReport(xml, nodeMeta)

		Expect(err).ToNot(HaveOccurred())
		Expect([]string{result.RuleResults[0].RuleID, result.RuleResults[1].RuleID}).To(Equal([]string{"SEC-A", "SEC-B"}))
	})
})

var _ = Describe("MergeRulesetResults", func() {
	It("should return an empty result for no inputs", func() {
		Expect(parser.MergeRulesetResults(nil)).To(Equal(ruleset.RulesetResult{}))
	})

	It("should return the single input unchanged", func() {
		in := ruleset.RulesetResult{
			RulesetID: "id",
			RuleResults: []rule.RuleResult{
				{RuleID: "R1", CheckResults: []rule.CheckResult{{Status: rule.Passed}}},
			},
		}

		Expect(parser.MergeRulesetResults([]ruleset.RulesetResult{in})).To(Equal(in))
	})

	It("should append check results of matching rules while preserving base fields", func() {
		base := ruleset.RulesetResult{
			RulesetID:      "rs-id",
			RulesetName:    "rs-name",
			RulesetVersion: "v1",
			RuleResults: []rule.RuleResult{
				{
					RuleID:       "R1",
					RuleName:     "Rule One",
					CheckResults: []rule.CheckResult{{Status: rule.Passed, Target: rule.NewTarget("name", "node-1")}},
				},
			},
		}
		other := ruleset.RulesetResult{
			RuleResults: []rule.RuleResult{
				{RuleID: "R1", CheckResults: []rule.CheckResult{{Status: rule.Failed, Target: rule.NewTarget("name", "node-2")}}},
			},
		}

		merged := parser.MergeRulesetResults([]ruleset.RulesetResult{base, other})

		Expect(merged).To(Equal(ruleset.RulesetResult{
			RulesetID:      "rs-id",
			RulesetName:    "rs-name",
			RulesetVersion: "v1",
			RuleResults: []rule.RuleResult{
				{
					RuleID:   "R1",
					RuleName: "Rule One",
					CheckResults: []rule.CheckResult{
						{Status: rule.Passed, Target: rule.NewTarget("name", "node-1")},
						{Status: rule.Failed, Target: rule.NewTarget("name", "node-2")},
					},
				},
			},
		}))
	})

	It("should include rules that appear only in later results", func() {
		base := ruleset.RulesetResult{
			RuleResults: []rule.RuleResult{
				{RuleID: "R1", CheckResults: []rule.CheckResult{{Status: rule.Passed}}},
			},
		}
		other := ruleset.RulesetResult{
			RuleResults: []rule.RuleResult{
				{RuleID: "R1", CheckResults: []rule.CheckResult{{Status: rule.Passed}}},
				{RuleID: "R2", CheckResults: []rule.CheckResult{{Status: rule.Failed}}},
			},
		}

		merged := parser.MergeRulesetResults([]ruleset.RulesetResult{base, other})

		Expect(merged.RuleResults).To(Equal([]rule.RuleResult{
			{RuleID: "R1", CheckResults: []rule.CheckResult{{Status: rule.Passed}, {Status: rule.Passed}}},
			{RuleID: "R2", CheckResults: []rule.CheckResult{{Status: rule.Failed}}},
		}))
	})

	It("should not mutate the base result's check results", func() {
		base := ruleset.RulesetResult{
			RuleResults: []rule.RuleResult{
				{RuleID: "R1", CheckResults: []rule.CheckResult{{Status: rule.Passed}}},
			},
		}
		other := ruleset.RulesetResult{
			RuleResults: []rule.RuleResult{
				{RuleID: "R1", CheckResults: []rule.CheckResult{{Status: rule.Failed}}},
			},
		}

		parser.MergeRulesetResults([]ruleset.RulesetResult{base, other})

		Expect(base.RuleResults[0].CheckResults).To(HaveLen(1))
	})
})
