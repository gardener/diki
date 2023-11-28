// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242452{}

type Rule242452 struct{}

func (r *Rule242452) ID() string {
	return ID242452
}

func (r *Rule242452) Name() string {
	return "Kubernetes kubelet config must have file permissions set to 644 or more restrictive (MEDIUM 242452)"
}

func (r *Rule242452) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule implemented by "node-files" for correctness, consistency, deduplication, reliability, and performance reasons.`, rule.NewTarget())), nil
}
