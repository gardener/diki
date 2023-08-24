// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242460{}

type Rule242460 struct{}

func (r *Rule242460) ID() string {
	return ID242460
}

func (r *Rule242460) Name() string {
	return "Kubernetes admin.conf must have file permissions set to 644 or more restrictive (MEDIUM 242460)"
}

func (r *Rule242460) Run(ctx context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Gardener does not use "kubeadm" and also does not store any "main config" anywhere in seed or shoot (flow/component logic built-in/in-code).`, gardener.NewTarget())), nil
}
