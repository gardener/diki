// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242459{}

type Rule242459 struct{}

func (r *Rule242459) ID() string {
	return ID242459
}

func (r *Rule242459) Name() string {
	return "Kubernetes etcd must have file permissions set to 644 or more restrictive (MEDIUM 242459)"
}

func (r *Rule242459) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule is implemented by the "pod-files" rule for correctness, consistency, deduplication, reliability, and performance reasons.`, rule.NewTarget())), nil
}
