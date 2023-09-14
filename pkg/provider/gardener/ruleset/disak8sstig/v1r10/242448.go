// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242448{}

type Rule242448 struct{}

func (r *Rule242448) ID() string {
	return ID242448
}

func (r *Rule242448) Name() string {
	return "Kubernetes Kube Proxy must be owned by root (MEDIUM 242448)"
}

func (r *Rule242448) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule is implemented by the "pod-files" rule for correctness, consistency, deduplication, reliability, and performance reasons.`, gardener.NewTarget())), nil
}
