// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"context"
)

var _ Rule = &SkipRule{}
var _ Severity = &SkipRule{}

// SkipRule is a Rule that always reports a predefined status.
type SkipRule struct {
	id            string
	name          string
	severity      SeverityLevel
	justification string
	status        Status
}

// Option is an interface that allows adding additional parameters to the SkipRule instances
type Option func(*SkipRule)

// WithSeverity returns an Option method that adds a Severity value to the SkipRule instance
func WithSeverity(severity SeverityLevel) Option {
	return func(skipRule *SkipRule) {
		skipRule.severity = severity
	}
}

// NewSkipRule returns a new skipped Rule.
func NewSkipRule(id, name, justification string, status Status, optionalParameters ...Option) *SkipRule {
	skipRule := &SkipRule{
		id:            id,
		name:          name,
		justification: justification,
		status:        status,
	}

	for _, option := range optionalParameters {
		option(skipRule)
	}

	return skipRule
}

// ID returns the id of the Rule.
func (s *SkipRule) ID() string {
	return s.id
}

// Name returns the name of the Rule.
func (s *SkipRule) Name() string {
	return s.name
}

// Severity returns the severity level of the Rule
func (s *SkipRule) Severity() SeverityLevel {
	return s.severity
}

// Run immediately returns a RuleResult containing
// a single CheckResult with a predefined status and justification.
func (s *SkipRule) Run(context.Context) (RuleResult, error) {
	return Result(s, []CheckResult{
		{
			Status:  s.status,
			Message: s.justification,
		},
	}...), nil
}
