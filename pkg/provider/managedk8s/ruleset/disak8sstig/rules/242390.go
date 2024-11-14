// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gardener/diki/pkg/rule"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var (
	_ rule.Rule     = &Rule242390{}
	_ rule.Severity = &Rule242390{}
)

type Rule242390 struct {
	Client          *http.Client
	KAPIExternalURL string
}

func (r *Rule242390) ID() string {
	return sharedrules.ID242390
}

func (r *Rule242390) Name() string {
	return "The Kubernetes API server must have anonymous authentication disabled."
}

func (r *Rule242390) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule242390) Run(ctx context.Context) (rule.RuleResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.KAPIExternalURL, nil)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(fmt.Sprintf("could not create request: %s", err.Error()), rule.NewTarget())), nil
	}

	response, err := r.Client.Do(request)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(fmt.Sprintf("could not access kube-apiserver: %s", err.Error()), rule.NewTarget())), nil
	}

	if response.StatusCode >= 500 && response.StatusCode <= 599 {
		return rule.Result(r, rule.WarningCheckResult("Cannot determine if anonymous authentication is enabled for the kube-apiserver.", rule.NewTarget("details", "the request returned 5xx status code"))), nil
	} else if response.StatusCode == http.StatusUnauthorized {
		return rule.Result(r, rule.PassedCheckResult("The kube-apiserver has anonymous authentication disabled.", rule.NewTarget())), nil
	}
	return rule.Result(r, rule.FailedCheckResult("The kube-apiserver has anonymous authentication enabled.", rule.NewTarget())), nil
}
