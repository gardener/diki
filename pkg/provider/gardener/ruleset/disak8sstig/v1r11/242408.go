// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242408{}

type Rule242408 struct{}

func (r *Rule242408) ID() string {
	return ID242408
}

func (r *Rule242408) Name() string {
	return "Kubernetes manifests must have least privileges (MEDIUM 242408)"
}

func (r *Rule242408) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult("Gardener does not deploy any control plane component as systemd processes or static pod.", gardener.NewTarget())), nil
}
