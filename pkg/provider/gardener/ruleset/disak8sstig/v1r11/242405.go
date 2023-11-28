// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242405{}

type Rule242405 struct{}

func (r *Rule242405) ID() string {
	return ID242405
}

func (r *Rule242405) Name() string {
	return "Kubernetes manifests must be owned by root (MEDIUM 242405)"
}

func (r *Rule242405) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult("Gardener does not deploy any control plane component as systemd processes or static pod.", rule.NewTarget())), nil
}
