// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package retry

import "github.com/gardener/diki/pkg/rule"

// CreateOption is a function that acts on a [RetryableRule]
// and is used to construct such objects.
type CreateOption func(*RetryableRule)

// WithBaseRule sets the BaseRule of a [RetryableRule].
func WithBaseRule(baseRule rule.Rule) CreateOption {
	return func(rr *RetryableRule) {
		rr.BaseRule = baseRule
	}
}

// WithMaxRetries sets the MaxRetries of a [RetryableRule].
func WithMaxRetries(maxRetries int) CreateOption {
	return func(rr *RetryableRule) {
		if maxRetries < 0 {
			panic("maxRetries should not be a negative number")
		}
		rr.MaxRetries = maxRetries
	}
}

// WithRetryCondition sets the RetryCondition of a [RetryableRule].
func WithRetryCondition(retryCondition func(ruleResult rule.RuleResult) bool) CreateOption {
	return func(rr *RetryableRule) {
		rr.RetryCondition = retryCondition
	}
}

// WithLogger the logger of a [RetryableRule].
func WithLogger(logger Logger) CreateOption {
	return func(rr *RetryableRule) {
		rr.Logger = logger
	}
}
