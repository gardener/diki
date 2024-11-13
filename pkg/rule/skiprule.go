// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"context"
)

var (
	_ Rule     = &SkipRule{}
	_ Severity = &SkipRule{}
)

// SkipRule is a Rule that always reports a predefined status.
type SkipRule struct {
	id            string
	name          string
	severity      SeverityLevel
	justification string
	status        Status
}

// SkipRuleOption allows to additionally configure a SkipRule.
type SkipRuleOption func(*SkipRule)

// SkipRuleWithSeverity allows configuring the severity of a SkipRule.
func SkipRuleWithSeverity(severity SeverityLevel) SkipRuleOption {
	return func(skipRule *SkipRule) {
		skipRule.severity = severity
	}
}

// NewSkipRule returns a new skipped Rule.
func NewSkipRule(id, name, justification string, status Status, options ...SkipRuleOption) *SkipRule {
	skipRule := &SkipRule{
		id:            id,
		name:          name,
		justification: justification,
		status:        status,
	}

	for _, option := range options {
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

// Severity returns the severity level of the Rule.
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
