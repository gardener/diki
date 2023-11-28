// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242450{}

type Rule242450 struct{}

func (r *Rule242450) ID() string {
	return ID242450
}

func (r *Rule242450) Name() string {
	return "Kubernetes Kubelet certificate authority must be owned by root (MEDIUM 242450)"
}

func (r *Rule242450) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule implemented by "node-files" for correctness, consistency, deduplication, reliability, and performance reasons.`, rule.NewTarget())), nil
}
