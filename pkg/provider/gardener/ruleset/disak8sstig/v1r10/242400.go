// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"
	"fmt"
	"log/slog"

	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242400{}

type Rule242400 struct {
	Client    client.Client
	Namespace string
	Logger    *slog.Logger
}

func (r *Rule242400) ID() string {
	return ID242400
}

func (r *Rule242400) Name() string {
	return "Kubernetes API server must have Alpha APIs disabled (MEDIUM 242400)"
}

func (r *Rule242400) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		kapiName = "kube-apiserver"
		option   = "feature-gates.AllAlpha"
	)
	target := gardener.NewTarget("cluster", "seed", "name", kapiName, "namespace", r.Namespace, "kind", "deployment")

	fgOptSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, kapiName, kapiName, r.Namespace, "feature-gates")
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	allAlphaOptSlice := kubeutils.FindInnerValue(fgOptSlice, "AllAlpha")

	// empty options are allowed because feature-gates.AllAlpha defaults to false
	switch {
	case len(allAlphaOptSlice) == 0:
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s has not been set.", option), target)), nil
	case len(allAlphaOptSlice) > 1:
		return rule.SingleCheckResult(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target)), nil
	case allAlphaOptSlice[0] == "true":
		return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), target)), nil
	case allAlphaOptSlice[0] == "false":
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target)), nil
	default:
		return rule.SingleCheckResult(r, rule.WarningCheckResult(fmt.Sprintf("Option %s set to neither 'true' nor 'false'.", option), target)), nil
	}
}
