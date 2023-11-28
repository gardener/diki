// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242377{}

type Rule242377 struct {
	Client    client.Client
	Namespace string
	Logger    *slog.Logger
}

func (r *Rule242377) ID() string {
	return ID242377
}

func (r *Rule242377) Name() string {
	return "Kubernetes Scheduler must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination (MEDIUM 242377)"
}

func (r *Rule242377) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		ksName = "kube-scheduler"
		option = "tls-min-version"
	)
	target := rule.NewTarget("cluster", "seed", "name", ksName, "namespace", r.Namespace, "kind", "deployment")

	optSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, ksName, ksName, r.Namespace, option)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	// empty options are allowed because min version defaults to TLS 1.2
	switch {
	case len(optSlice) == 0:
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s has not been set.", option), target)), nil
	case len(optSlice) > 1:
		return rule.SingleCheckResult(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target)), nil
	case slices.Contains([]string{"VersionTLS10", "VersionTLS11"}, optSlice[0]):
		return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), target)), nil
	default:
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target)), nil
	}
}
