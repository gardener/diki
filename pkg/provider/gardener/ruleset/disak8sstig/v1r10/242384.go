// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242384{}

type Rule242384 struct{}

func (r *Rule242384) ID() string {
	return ID242384
}

func (r *Rule242384) Name() string {
	return "Kubernetes Scheduler must have secure binding (MEDIUM 242384)"
}

func (r *Rule242384) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`The Kubernetes Scheduler runs in a container which already has limited access to network interfaces. In addition ingress traffic to the Kubernetes Scheduler is restricted via network policies, making an unintended exposure less likely.`, rule.NewTarget())), nil
}
