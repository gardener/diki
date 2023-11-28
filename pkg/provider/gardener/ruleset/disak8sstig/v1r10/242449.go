// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242449{}

type Rule242449 struct{}

func (r *Rule242449) ID() string {
	return ID242449
}

func (r *Rule242449) Name() string {
	return "Kubernetes Kubelet certificate authority file must have file permissions set to 644 or more restrictive (MEDIUM 242449)"
}

func (r *Rule242449) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule implemented by "node-files" for correctness, consistency, deduplication, reliability, and performance reasons.`, rule.NewTarget())), nil
}
