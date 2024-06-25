// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package retry_test

import (
	"context"
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/rule/retry"
)

var _ = Describe("retryable_rule", func() {
	Describe("#RetryableRule", func() {
		var (
			trueRetryCondition = func(_ rule.RuleResult) bool {
				return true
			}
			falseRetryCondition = func(_ rule.RuleResult) bool {
				return false
			}
			simpleRetryCondition = func(ruleResult rule.RuleResult) bool {
				for _, checkResult := range ruleResult.CheckResults {
					if checkResult.Status == rule.Errored {
						if checkResult.Message == "foo" {
							return true
						}
					}
				}
				return false
			}
			ctx = context.TODO()
		)
		BeforeEach(func() {
			counter = 0
		})

		DescribeTable("Run cases", func(retryCondition func(ruleResult rule.RuleResult) bool, maxRetries, expectedCounter int) {
			sr := &simpleRule{}
			rr := retry.RetryableRule{
				BaseRule:       sr,
				MaxRetries:     maxRetries,
				RetryCondition: retryCondition,
				Logger:         testLogger,
			}

			_, err := rr.Run(ctx)

			Expect(err).To(BeNil())
			Expect(counter).To(Equal(expectedCounter))
		},
			Entry("should hit maxRetry when retry condition is always met", trueRetryCondition, 7, 7),
			Entry("should retry only once when retry condition is not met", falseRetryCondition, 7, 1),
			Entry("should retry until retry condition is not met", simpleRetryCondition, 7, 5),
		)
	})

	Describe("#RetryConditionFromRegex", func() {
		var (
			fooRegex       = regexp.MustCompile(`(?i)(foo)`)
			barRegex       = regexp.MustCompile(`(?i)(bar)`)
			fooCheckResult rule.CheckResult
			barCheckResult rule.CheckResult
			simpleRule     simpleRule
		)

		BeforeEach(func() {
			fooCheckResult = rule.CheckResult{
				Status:  rule.Errored,
				Message: "foo",
				Target:  rule.NewTarget(),
			}
			barCheckResult = rule.CheckResult{
				Status:  rule.Errored,
				Message: "bar",
				Target:  rule.NewTarget(),
			}
		})

		It("should create retry condition from a single regex", func() {
			rc := retry.RetryConditionFromRegex(*fooRegex)

			result := rc(rule.SingleCheckResult(&simpleRule, fooCheckResult))
			Expect(result).To(Equal(true))

			result = rc(rule.SingleCheckResult(&simpleRule, barCheckResult))
			Expect(result).To(Equal(false))

			fooCheckResult.Status = rule.Passed
			result = rc(rule.SingleCheckResult(&simpleRule, fooCheckResult))
			Expect(result).To(Equal(false))
		})
		It("should create retry condition from multiple regexes", func() {
			rc := retry.RetryConditionFromRegex(*fooRegex, *barRegex)

			result := rc(rule.SingleCheckResult(&simpleRule, fooCheckResult))
			Expect(result).To(Equal(true))

			result = rc(rule.SingleCheckResult(&simpleRule, barCheckResult))
			Expect(result).To(Equal(true))

			fooCheckResult.Status = rule.Passed
			result = rc(rule.SingleCheckResult(&simpleRule, fooCheckResult))
			Expect(result).To(Equal(false))
		})
	})
})

var counter = 0
var _ rule.Rule = &simpleRule{}

type simpleRule struct{}

func (r *simpleRule) ID() string {
	return "1"
}

func (r *simpleRule) Name() string {
	return "Simple rule"
}

func (r *simpleRule) Run(_ context.Context) (rule.RuleResult, error) {
	counter++
	if counter > 4 {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult("bar", rule.NewTarget())), nil
	}
	return rule.SingleCheckResult(r, rule.ErroredCheckResult("foo", rule.NewTarget())), nil
}
