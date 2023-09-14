// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242468{}

type Rule242468 struct{}

func (r *Rule242468) ID() string {
	return ID242468
}

func (r *Rule242468) Name() string {
	return "Kubernetes API Server must prohibit communication using TLS version 1.0 and 1.1, and SSL 2.0 and 3.0 (MEDIUM 242468)"
}

func (r *Rule242468) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule is duplicate of "242378"`, gardener.NewTarget())), nil
}
