// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242457{}

type Rule242457 struct{}

func (r *Rule242457) ID() string {
	return ID242457
}

func (r *Rule242457) Name() string {
	return "Kubernetes kubelet config must be owned by root (MEDIUM 242457)"
}

func (r *Rule242457) Run(ctx context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule is duplicate of "242453".`, gardener.NewTarget())), nil
}
