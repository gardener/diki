// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242421{}

type Rule242421 struct {
	Client    client.Client
	Namespace string
	Logger    *slog.Logger
}

func (r *Rule242421) ID() string {
	return ID242421
}

func (r *Rule242421) Name() string {
	return "Kubernetes Controller Manager must have the SSL Certificate Authority set (MEDIUM 242421)"
}

func (r *Rule242421) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		kcmName = "kube-controller-manager"
		option  = "root-ca-file"
	)
	target := rule.NewTarget("cluster", "seed", "name", kcmName, "namespace", r.Namespace, "kind", "deployment")

	optSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, kcmName, kcmName, r.Namespace, option)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	switch {
	case len(optSlice) == 0:
		return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s has not been set.", option), target)), nil
	case len(optSlice) > 1:
		return rule.SingleCheckResult(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target)), nil
	case strings.TrimSpace(optSlice[0]) == "":
		return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s is empty.", option), target)), nil
	default:
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set.", option), target)), nil
	}
}
