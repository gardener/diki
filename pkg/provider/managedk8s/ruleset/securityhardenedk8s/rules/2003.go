// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule2003{}
	_ rule.Severity = &Rule2003{}
)

type Rule2003 struct {
}

func (r *Rule2003) ID() string {
	return "2003"
}

func (r *Rule2003) Name() string {
	return "Pods should use only allowed volume types."
}

func (r *Rule2003) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule2003) Run(ctx context.Context) (rule.RuleResult, error) {

}
