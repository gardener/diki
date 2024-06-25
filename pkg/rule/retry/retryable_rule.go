// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package retry

import (
	"context"
	"log/slog"
	"regexp"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &RetryableRule{}

// RetryableRule wraps Rules, it allows rule runs to be retried when the RetryCondition is met
type RetryableRule struct {
	BaseRule       rule.Rule
	MaxRetries     int
	RetryCondition func(ruleResult rule.RuleResult) bool
	Logger         *slog.Logger
}

// ID is a getter for rule id
func (rr *RetryableRule) ID() string {
	return rr.BaseRule.ID()
}

// Name is a getter for rule name
func (rr *RetryableRule) Name() string {
	return rr.BaseRule.Name()
}

// Run executes the baseRule and retries when RetryCondition is met
func (rr *RetryableRule) Run(ctx context.Context) (rule.RuleResult, error) {
	var res rule.RuleResult
	var err error
	for i := 1; i <= rr.MaxRetries; i++ {
		res, err = rr.BaseRule.Run(ctx)
		if !rr.RetryCondition(res) || err != nil {
			break
		}
		if i < rr.MaxRetries {
			rr.Logger.Info("retrying rule run", "rule_id", rr.ID(), "left_retries", rr.MaxRetries-i)
		}
	}
	return res, err
}

// RetryConditionFromRegex generates RetryCondition func from regexes
func RetryConditionFromRegex(regexes ...regexp.Regexp) func(ruleResult rule.RuleResult) bool {
	return func(ruleResult rule.RuleResult) bool {
		for _, checkResult := range ruleResult.CheckResults {
			if checkResult.Status == rule.Errored {
				for _, regex := range regexes {
					if regex.MatchString(checkResult.Message) {
						return true
					}
				}
			}
		}
		return false
	}
}
