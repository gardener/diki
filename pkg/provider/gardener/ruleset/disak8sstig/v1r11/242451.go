// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242451{}

type Rule242451 struct{}

func (r *Rule242451) ID() string {
	return ID242451
}

func (r *Rule242451) Name() string {
	return "Kubernetes component PKI must be owned by root (MEDIUM 242451)"
}

func (r *Rule242451) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule implemented by "node-files" for correctness, consistency, deduplication, reliability, and performance reasons.`, gardener.NewTarget())), nil
}
