// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242407{}

type Rule242407 struct{}

func (r *Rule242407) ID() string {
	return ID242407
}

func (r *Rule242407) Name() string {
	return "Kubernetes kubelet configuration files must have file permissions set to 644 or more restrictive (MEDIUM 242407)"
}

func (r *Rule242407) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule implemented by "node-files" for correctness, consistency, deduplication, reliability, and performance reasons.`, gardener.NewTarget())), nil
}
