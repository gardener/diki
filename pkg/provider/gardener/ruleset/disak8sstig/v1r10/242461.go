// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242461{}

type Rule242461 struct{}

func (r *Rule242461) ID() string {
	return ID242461
}

func (r *Rule242461) Name() string {
	return "Kubernetes API Server audit logs must be enabled (MEDIUM 242461)"
}

func (r *Rule242461) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule is duplicate of "242401"`, rule.NewTarget())), nil
}
