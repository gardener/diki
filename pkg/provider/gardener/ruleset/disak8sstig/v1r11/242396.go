// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242396{}

type Rule242396 struct{}

func (r *Rule242396) ID() string {
	return ID242396
}

func (r *Rule242396) Name() string {
	return "Kubernetes Kubectl cp command must give expected access and results (MEDIUM 242396)"
}

func (r *Rule242396) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`"kubectl" is not installed into control plane pods or worker nodes and Gardener does not offer Kubernetes v1.12 or older.`, gardener.NewTarget())), nil
}
