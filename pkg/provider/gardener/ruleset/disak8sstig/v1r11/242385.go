// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242385{}

type Rule242385 struct{}

func (r *Rule242385) ID() string {
	return ID242385
}

func (r *Rule242385) Name() string {
	return "Kubernetes Controller Manager must have secure binding (MEDIUM 242385)"
}

func (r *Rule242385) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`The Kubernetes Controller Manager runs in a container which already has limited access to network interfaces. In addition ingress traffic to the Kubernetes Controller Manager is restricted via network policies, making an unintended exposure less likely.`, gardener.NewTarget())), nil
}
