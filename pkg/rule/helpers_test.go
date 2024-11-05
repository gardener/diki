// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rule_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("utils", func() {

	Describe("#Result", func() {
		It("should return the correct result", func() {
			result := rule.Result(&fakeRule{}, rule.CheckResult{Status: rule.Passed, Message: "foo", Target: rule.Target{}})
			Expect(result).To(Equal(rule.RuleResult{
				RuleName:     "name",
				RuleID:       "id",
				CheckResults: []rule.CheckResult{{Status: rule.Passed, Message: "foo", Target: rule.Target{}}},
			}))
		})
	})

	DescribeTable("#GetCheckResult",
		func(checkResultFunc func(message string, target rule.Target) rule.CheckResult, message string, target rule.Target, expectedCheckResult rule.CheckResult) {
			checkResult := checkResultFunc(message, target)

			Expect(checkResult).To(Equal(expectedCheckResult))
		},
		Entry("PassedCheckResult should return correct rule.CheckResult",
			rule.PassedCheckResult, "foo", rule.NewTarget("cluster", "bar"), rule.CheckResult{
				Status:  rule.Passed,
				Message: "foo",
				Target:  rule.NewTarget("cluster", "bar"),
			}),
		Entry("AcceptedCheckResult should return correct rule.CheckResult",
			rule.AcceptedCheckResult, "foo", rule.NewTarget("cluster", "bar"), rule.CheckResult{
				Status:  rule.Accepted,
				Message: "foo",
				Target:  rule.NewTarget("cluster", "bar"),
			}),
		Entry("FailedCheckResult should return correct rule.CheckResult",
			rule.FailedCheckResult, "foo", rule.NewTarget("cluster", "bar"), rule.CheckResult{
				Status:  rule.Failed,
				Message: "foo",
				Target:  rule.NewTarget("cluster", "bar"),
			}),
		Entry("ErroredCheckResult should return correct rule.CheckResult",
			rule.ErroredCheckResult, "foo", rule.NewTarget("cluster", "bar"), rule.CheckResult{
				Status:  rule.Errored,
				Message: "foo",
				Target:  rule.NewTarget("cluster", "bar"),
			}),
		Entry("NotImplementedCheckResult should return correct rule.CheckResult",
			rule.NotImplementedCheckResult, "foo", rule.NewTarget("cluster", "bar"), rule.CheckResult{
				Status:  rule.NotImplemented,
				Message: "foo",
				Target:  rule.NewTarget("cluster", "bar"),
			}),
		Entry("WarningCheckResult should return correct rule.CheckResult",
			rule.WarningCheckResult, "foo", rule.NewTarget("cluster", "bar"), rule.CheckResult{
				Status:  rule.Warning,
				Message: "foo",
				Target:  rule.NewTarget("cluster", "bar"),
			}),
		Entry("SkippedCheckResult should return correct rule.CheckResult",
			rule.SkippedCheckResult, "foo", rule.NewTarget("cluster", "bar"), rule.CheckResult{
				Status:  rule.Skipped,
				Message: "foo",
				Target:  rule.NewTarget("cluster", "bar"),
			}),
	)

})

type fakeRule struct{}

func (*fakeRule) ID() string {
	return "id"
}

func (*fakeRule) Name() string {
	return "name"
}

func (*fakeRule) Run(context.Context) (rule.RuleResult, error) {
	return rule.RuleResult{}, nil
}
