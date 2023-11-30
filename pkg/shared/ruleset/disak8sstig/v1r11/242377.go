// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242377{}

type Rule242377 struct{}

func (r *Rule242377) ID() string {
	return ID242377
}

func (r *Rule242377) Name() string {
	return "The Kubernetes Scheduler must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination (MEDIUM 242376)"
}

func (r *Rule242377) Run(ctx context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`The Virtual Garden cluster does not make use of a Kubernetes Scheduler.`, rule.NewTarget())), nil
}
