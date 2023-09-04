// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242458{}

type Rule242458 struct{}

func (r *Rule242458) ID() string {
	return ID242458
}

func (r *Rule242458) Name() string {
	return "Kubernetes API Server must have file permissions set to 644 or more restrictive (MEDIUM 242458)"
}

func (r *Rule242458) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult("Gardener does not deploy any control plane component as systemd processes or static pod.", gardener.NewTarget())), nil
}
