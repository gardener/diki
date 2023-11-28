// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242383{}

type Rule242383 struct{}

func (r *Rule242383) ID() string {
	return ID242383
}

func (r *Rule242383) Name() string {
	return "User-managed resources must be created in dedicated namespaces (HIGH 242383)"
}

func (r *Rule242383) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`By definition, all resources that Gardener creates are no end-user resources.`, rule.NewTarget())), nil
}
