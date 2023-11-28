// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242465{}

type Rule242465 struct{}

func (r *Rule242465) ID() string {
	return ID242465
}

func (r *Rule242465) Name() string {
	return "Kubernetes API Server audit log path must be set (MEDIUM 242465)"
}

func (r *Rule242465) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule is duplicate of "242402"`, rule.NewTarget())), nil
}
