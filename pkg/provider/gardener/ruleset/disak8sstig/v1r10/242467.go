// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242467{}

type Rule242467 struct{}

func (r *Rule242467) ID() string {
	return ID242467
}

func (r *Rule242467) Name() string {
	return "Kubernetes PKI keys must have file permissions set to 600 or more restrictive (MEDIUM 242467)"
}

func (r *Rule242467) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule implemented by "node-files" and "pod-files" for correctness, consistency, deduplication, reliability, and performance reasons.`, rule.NewTarget())), nil
}
