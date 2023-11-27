// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242445{}

type Rule242445 struct{}

func (r *Rule242445) ID() string {
	return ID242445
}

func (r *Rule242445) Name() string {
	return "Kubernetes component etcd must be owned by etcd (MEDIUM 242445)"
}

func (r *Rule242445) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Gardener does not deploy any control plane component as systemd processes or static pod. It is deployed as regular pod under root:root, not readable by non-root users, which is checked by "pod-files" for correctness, consistency, deduplication, reliability, and performance reasons.`, gardener.NewTarget())), nil
}
