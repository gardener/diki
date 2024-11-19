// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule2006{}
	_ rule.Severity = &Rule2006{}
)

type Rule2006 struct {
}

func (r *Rule2006) ID() string {
	return "2006"
}

func (r *Rule2006) Name() string {
	return "Shoot clusters must have static token kubeconfig disabled."
}

func (r *Rule2006) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule2006) Run(ctx context.Context) (rule.RuleResult, error) {

}
