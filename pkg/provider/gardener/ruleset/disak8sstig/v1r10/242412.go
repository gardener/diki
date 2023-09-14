// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242412{}

type Rule242412 struct{}

func (r *Rule242412) ID() string {
	return ID242412
}

func (r *Rule242412) Name() string {
	return "Kubernetes Controllers must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) (MEDIUM 242412)"
}

func (r *Rule242412) Run(_ context.Context) (rule.RuleResult, error) {
	return rule.SingleCheckResult(r, rule.SkippedCheckResult(`Cannot be tested and should be enforced organizationally. Gardener uses a minimum of known and automatically opened/used/created ports/protocols/services (PPSM stands for Ports, Protocols, Service Management).`, gardener.NewTarget())), nil
}
