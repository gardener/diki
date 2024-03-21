// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"context"
)

var _ Rule = &SkipRule{}

// SkipRule is a Rule that always reports a predefined status.
type SkipRule struct {
	id            string
	name          string
	justification string
	status        Status
}

// NewSkipRule returns a new skipped Rule.
func NewSkipRule(id, name, justification string, status Status) *SkipRule {
	return &SkipRule{
		id:            id,
		name:          name,
		justification: justification,
		status:        status,
	}
}

// ID returns the id of the Rule.
func (s *SkipRule) ID() string {
	return s.id
}

// Name returns the name of the Rule.
func (s *SkipRule) Name() string {
	return s.name
}

// Run immediately returns a RuleResult containing
// a single CheckResult with a predefined status and justification.
func (s *SkipRule) Run(context.Context) (RuleResult, error) {
	return RuleResult{
		RuleID:   s.ID(),
		RuleName: s.Name(),
		CheckResults: []CheckResult{
			{
				Status:  s.status,
				Message: s.justification,
			},
		},
	}, nil
}
