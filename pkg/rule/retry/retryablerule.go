// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package retry

import (
	"context"
	"math"
	"regexp"
	"time"

	"github.com/gardener/diki/pkg/rule"
)

type logger interface {
	Info(string, ...any)
}

var _ rule.Rule = &RetryableRule{}

// RetryableRule wraps [rule.Rule] and allows a rule to be retried when the retry condition is met.
type RetryableRule struct {
	BaseRule       rule.Rule
	MaxRetries     int
	RetryCondition func(ruleResult rule.RuleResult) bool
	Logger         logger
}

// ID returns the id of the rule.
func (rr *RetryableRule) ID() string {
	return rr.BaseRule.ID()
}

// Name returns the name of the rule.
func (rr *RetryableRule) Name() string {
	return rr.BaseRule.Name()
}

// Run executes the base rule and retries when the retry condition is met and max retries are not reached yet.
func (rr *RetryableRule) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		res rule.RuleResult
		err error
	)

	for i := 0; i <= rr.MaxRetries; i++ {
		res, err = rr.BaseRule.Run(ctx)
		if !rr.RetryCondition(res) || err != nil {
			break
		}
		if i < rr.MaxRetries {
			waitDuration := math.Pow(2, float64(i))

			rr.Logger.Info("waiting to retry run", "wait_duration_seconds", waitDuration)
			sleepDuration := time.Duration(waitDuration * float64(time.Second))
			time.Sleep(sleepDuration)

			rr.Logger.Info("retrying run", "retry_attempt", i+1)
		}
	}
	return res, err
}

// RetryConditionFromRegex generates a retry condition func that matches messages from [rule.Errored] statuses.
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
