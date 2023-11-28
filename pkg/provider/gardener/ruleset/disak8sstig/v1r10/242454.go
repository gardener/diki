// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242454{}

type Rule242454 struct{}

func (r *Rule242454) ID() string {
	return ID242454
}

func (r *Rule242454) Name() string {
	return "Kubernetes kubeadm.conf must be owned by root(MEDIUM 242454)"
}

func (r *Rule242454) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Gardener does not use "kubeadm" and also does not store any "main config" anywhere in seed or shoot (flow/component logic built-in/in-code).`, rule.NewTarget())), nil
}
