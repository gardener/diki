// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"net/http"

	"github.com/gardener/diki/pkg/rule"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ rule.Rule = &Rule242390{}

type Rule242390 struct {
	InstanceID      string
	Client          *http.Client
	KAPIExternalURL string
}

func (r *Rule242390) ID() string {
	return sharedrules.ID242390
}

func (r *Rule242390) Name() string {
	return "The Kubernetes API server must have anonymous authentication disabled (HIGH 242390)"
}

func (r *Rule242390) Run(_ context.Context) (rule.RuleResult, error) {
	httpResponse, err := r.Client.Get(r.KAPIExternalURL)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult("failed to access the kube-apiserver", rule.NewTarget())), nil
	}

	if httpResponse.StatusCode == http.StatusForbidden {
		return rule.SingleCheckResult(r, rule.PassedCheckResult("kube-apiserver has anonymous authentication disabled", rule.NewTarget())), nil
	} else {
		return rule.SingleCheckResult(r, rule.FailedCheckResult("kube-apiserver has anonymous authentication enabled", rule.NewTarget())), nil
	}
}
