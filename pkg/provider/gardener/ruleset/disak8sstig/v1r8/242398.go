// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242398{}

type Rule242398 struct{}

func (r *Rule242398) ID() string {
	return ID242398
}

func (r *Rule242398) Name() string {
	return "Kubernetes DynamicAuditing must not be enabled (MEDIUM 242398)"
}

func (r *Rule242398) Run(ctx context.Context) (rule.RuleResult, error) {
	// feature-gates.DynamicAuditing removed in v1.19. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Option feature-gates.DynamicAuditing removed in Kubernetes v1.19.`, gardener.NewTarget())), nil
}
