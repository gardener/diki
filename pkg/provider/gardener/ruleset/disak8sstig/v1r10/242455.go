// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242455{}

type Rule242455 struct{}

func (r *Rule242455) ID() string {
	return ID242455
}

func (r *Rule242455) Name() string {
	return "Kubernetes kubeadm.conf must have file permissions set to 644 or more restrictive (MEDIUM 242455)"
}

func (r *Rule242455) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Gardener does not use "kubeadm" and also does not store any "main config" anywhere in seed or shoot (flow/component logic built-in/in-code).`, rule.NewTarget())), nil
}
