// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242466{}

type Rule242466 struct{}

func (r *Rule242466) ID() string {
	return ID242466
}

func (r *Rule242466) Name() string {
	return "Kubernetes PKI CRT must have file permissions set to 644 or more restrictive (MEDIUM 242466)"
}

func (r *Rule242466) Run(ctx context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule implemented by "node-files" for correctness, consistency, deduplication, reliability, and performance reasons.`, gardener.NewTarget())), nil
}
