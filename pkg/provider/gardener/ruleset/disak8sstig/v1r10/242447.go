// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242447{}

type Rule242447 struct{}

func (r *Rule242447) ID() string {
	return ID242447
}

func (r *Rule242447) Name() string {
	return "Kubernetes Kube Proxy must have file permissions set to 644 or more restrictive (MEDIUM 242447)"
}

func (r *Rule242447) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule is implemented by the "pod-files" rule for correctness, consistency, deduplication, reliability, and performance reasons.`, gardener.NewTarget())), nil
}
