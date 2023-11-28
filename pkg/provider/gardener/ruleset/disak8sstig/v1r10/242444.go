// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242444{}

type Rule242444 struct{}

func (r *Rule242444) ID() string {
	return ID242444
}

func (r *Rule242444) Name() string {
	return "Kubernetes component manifests must be owned by root (MEDIUM 242444)"
}

func (r *Rule242444) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Rule is duplicate of "242405"`, rule.NewTarget())), nil
}
