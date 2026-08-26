// SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package junitreportparser_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/gardenlinux/junitreportparser"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
)

var _ = Describe("ParseXMLReport", func() {
	const (
		nodeName = "node-1"
		osImage  = "Garden Linux 1592.4"
	)

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
		Status:     corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{OSImage: osImage}},
	}

	// nodeTarget is the expected check target for the fixture node.
	nodeTarget := rule.NewTarget("kind", "Node", "name", nodeName, "osImage", osImage)

	// testcaseXML wraps a single <testcase> body in the enclosing testsuites/testsuite elements.
	// A default security_id property is appended so the testcase passes validation; inner may
	// contain its own <properties> element with additional properties.
	testcaseXML := func(inner string) string {
		return `<testsuites name="root">
	<testsuite name="s">
		<testcase name="tc" classname="C">` +
			inner +
			`<properties>
				<property name="security_id" value="SEC"/>
			</properties>
		</testcase>
	</testsuite>
</testsuites>`
	}

	DescribeTable("should reject or ignore reports that yield no rules",
		func(xml string, expectErr bool, expected ruleset.RulesetResult) {
			result, err := junitreportparser.ParseXMLReport(xml, node)

			if expectErr {
				Expect(err).To(HaveOccurred())
				return
			}

			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal(expected))
		},
		Entry("malformed XML",
			`<testsuites name="root"><testsuite>`,
			true, ruleset.RulesetResult{}),
		Entry("no testsuites",
			`<testsuites name="root"></testsuites>`,
			true, ruleset.RulesetResult{}),
		Entry("more than one testsuite",
			`<testsuites name="root">
	<testsuite name="a"></testsuite>
	<testsuite name="b"></testsuite>
</testsuites>`,
			true, ruleset.RulesetResult{}),
		Entry("testcase without properties",
			`<testsuites name="root">
	<testsuite name="s">
		<testcase name="tc" classname="C"></testcase>
	</testsuite>
</testsuites>`,
			true, ruleset.RulesetResult{}),
		Entry("testcase with an empty security_id",
			`<testsuites name="root">
	<testsuite name="s">
		<testcase name="tc" classname="C">
			<properties>
				<property name="security_id" value=""/>
			</properties>
		</testcase>
	</testsuite>
</testsuites>`,
			true, ruleset.RulesetResult{}),
		Entry("testcase with no security_id property",
			`<testsuites name="root">
	<testsuite name="s">
		<testcase name="tc" classname="C">
			<properties>
				<property name="docstring" value="x"/>
			</properties>
		</testcase>
	</testsuite>
</testsuites>`,
			true, ruleset.RulesetResult{}),
	)

	DescribeTable("should map a single testcase to the expected status and message",
		func(inner string, expectedStatus rule.Status, expectedMessage string) {
			result, err := junitreportparser.ParseXMLReport(testcaseXML(inner), node)

			Expect(err).ToNot(HaveOccurred())
			Expect(result.RuleResults[0].CheckResults[0]).To(Equal(rule.CheckResult{
				Status:  expectedStatus,
				Message: expectedMessage,
				Target:  nodeTarget,
			}))
		},
		Entry("passing testcase", ``, rule.Passed, ""),
		Entry("failure with message attr", `<failure message="fail"></failure>`, rule.Failed, "fail"),
		Entry("error with message attr", `<error message="err"></error>`, rule.Errored, "err"),
		Entry("skipped with message attr", `<skipped message="not applicable"></skipped>`, rule.Skipped, "not applicable"),
	)

	// TODO (georgibaltiev): Remove this testcase once the failure stdout dump has been resolved
	It("should truncate a failure message to its first line", func() {
		xml := testcaseXML(`<failure message="assertion failed&#10;full captured output&#10;more noise"></failure>`)

		result, err := junitreportparser.ParseXMLReport(xml, node)

		Expect(err).ToNot(HaveOccurred())
		Expect(result.RuleResults[0].CheckResults[0].Message).To(Equal("assertion failed"))
	})

	DescribeTable("should derive rule and check metadata from a single testcase",
		func(inner string, assertFunc func(rule.RuleResult)) {
			result, err := junitreportparser.ParseXMLReport(testcaseXML(inner), node)

			Expect(err).ToNot(HaveOccurred())
			Expect(result.RuleResults).To(HaveLen(1))
			assertFunc(result.RuleResults[0])
		},
		Entry("sets the node on the check target", ``, func(rr rule.RuleResult) {
			Expect(rr.CheckResults[0].Target).To(Equal(nodeTarget))
		}),
		Entry("uses the security_id property as the RuleID", ``, func(rr rule.RuleResult) {
			Expect(rr.RuleID).To(Equal("SEC"))
		}),
		Entry("derives the RuleName and check description from the docstring paragraphs",
			`<properties>
				<property name="docstring" value="Ref: Ref-1&#10;&#10;My Rule Name&#10;&#10;Check detail"/>
			</properties>`,
			func(rr rule.RuleResult) {
				Expect(rr).To(Equal(rule.RuleResult{
					RuleID:   "SEC",
					RuleName: "My Rule Name",
					CheckResults: []rule.CheckResult{
						{Status: rule.Passed, Message: "Check detail", Target: nodeTarget},
					},
				}))
			}),
		Entry("falls back to the classname when the docstring yields no rule name", ``, func(rr rule.RuleResult) {
			Expect(rr.RuleName).To(Equal("C"))
		}),
		Entry("derives the RuleName from a two-paragraph docstring with no check description",
			`<properties>
				<property name="docstring" value="Ref: Ref-1&#10;&#10;My Rule Name"/>
			</properties>`,
			func(rr rule.RuleResult) {
				Expect(rr).To(Equal(rule.RuleResult{
					RuleID:   "SEC",
					RuleName: "My Rule Name",
					CheckResults: []rule.CheckResult{
						{Status: rule.Passed, Message: "", Target: nodeTarget},
					},
				}))
			}),
		Entry("falls back to the classname when the docstring has fewer than two paragraphs",
			`<properties>
				<property name="docstring" value="Ref: Ref-1"/>
			</properties>`,
			func(rr rule.RuleResult) {
				Expect(rr).To(Equal(rule.RuleResult{
					RuleID:   "SEC",
					RuleName: "C",
					CheckResults: []rule.CheckResult{
						{Status: rule.Passed, Message: "", Target: nodeTarget},
					},
				}))
			}),
		Entry("falls back to the classname when the docstring has more than three paragraphs",
			`<properties>
				<property name="docstring" value="Ref: Ref-1&#10;&#10;My Rule Name&#10;&#10;Check detail&#10;&#10;extra"/>
			</properties>`,
			func(rr rule.RuleResult) {
				Expect(rr).To(Equal(rule.RuleResult{
					RuleID:   "SEC",
					RuleName: "C",
					CheckResults: []rule.CheckResult{
						{Status: rule.Passed, Message: "", Target: nodeTarget},
					},
				}))
			}),
		Entry("prefers the failure message attribute over the chardata text",
			`<failure message="attr">chardata</failure>`,
			func(rr rule.RuleResult) {
				Expect(rr.CheckResults[0].Message).To(Equal("attr"))
			}),
	)

	It("should group testcases sharing the same security_id into one rule", func() {
		xml := `<testsuites name="root">
	<testsuite name="s">
		<testcase name="a" classname="C">
			<properties>
				<property name="security_id" value="SEC-1"/>
				<property name="docstring" value="Ref 1&#10;&#10;Rule Name C&#10;&#10;first check"/>
			</properties>
		</testcase>
		<testcase name="b" classname="C">
			<failure message="bad"></failure>
			<properties>
				<property name="security_id" value="SEC-1"/>
				<property name="docstring" value="Ref 1&#10;&#10;Rule Name C&#10;&#10;second check"/>
			</properties>
		</testcase>
	</testsuite>
</testsuites>`

		result, err := junitreportparser.ParseXMLReport(xml, node)

		Expect(err).ToNot(HaveOccurred())
		Expect(result.RuleResults).To(Equal([]rule.RuleResult{
			{
				RuleID:   "SEC-1",
				RuleName: "Rule Name C",
				CheckResults: []rule.CheckResult{
					{
						Status:  rule.Passed,
						Message: "first check",
						Target:  nodeTarget,
					},
					{
						Status:  rule.Failed,
						Message: "second check - bad",
						Target:  nodeTarget,
					},
				},
			},
		}))
	})

	It("should deduplicate testcases sharing the same security_id that render to an identical check", func() {
		xml := `<testsuites name="root">
	<testsuite name="s">
		<testcase name="a" classname="C">
			<properties>
				<property name="security_id" value="SEC-1"/>
				<property name="docstring" value="Ref 1&#10;&#10;Rule Name C&#10;&#10;same check"/>
			</properties>
		</testcase>
		<testcase name="b" classname="C">
			<properties>
				<property name="security_id" value="SEC-1"/>
				<property name="docstring" value="Ref 1&#10;&#10;Rule Name C&#10;&#10;same check"/>
			</properties>
		</testcase>
	</testsuite>
</testsuites>`

		result, err := junitreportparser.ParseXMLReport(xml, node)

		Expect(err).ToNot(HaveOccurred())
		Expect(result.RuleResults).To(Equal([]rule.RuleResult{
			{
				RuleID:   "SEC-1",
				RuleName: "Rule Name C",
				CheckResults: []rule.CheckResult{
					{
						Status:  rule.Passed,
						Message: "same check",
						Target:  nodeTarget,
					},
				},
			},
		}))
	})
})

var _ = Describe("MergeRulesetResults", func() {
	It("should return an empty result for no inputs", func() {
		Expect(junitreportparser.MergeRulesetResults(nil)).To(Equal(ruleset.RulesetResult{}))
	})

	It("should return the single input unchanged", func() {
		in := ruleset.RulesetResult{
			RulesetID: "id",
			RuleResults: []rule.RuleResult{
				{RuleID: "R1", CheckResults: []rule.CheckResult{{Status: rule.Passed}}},
			},
		}

		Expect(junitreportparser.MergeRulesetResults([]ruleset.RulesetResult{in})).To(Equal(in))
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

		merged := junitreportparser.MergeRulesetResults([]ruleset.RulesetResult{base, other})

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

		merged := junitreportparser.MergeRulesetResults([]ruleset.RulesetResult{base, other})

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

		junitreportparser.MergeRulesetResults([]ruleset.RulesetResult{base, other})

		Expect(base.RuleResults[0].CheckResults).To(HaveLen(1))
	})
})
