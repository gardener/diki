// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242456{}

type Rule242456 struct{}

func (r *Rule242456) ID() string {
	return ID242456
}

func (r *Rule242456) Name() string {
	return "Kubernetes kubelet config must have file permissions set to 644 or more restrictive (MEDIUM 242456)"
}

func (r *Rule242456) Run(ctx context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule is duplicate of "242452".`, gardener.NewTarget())), nil
}
