// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242382{}

type Rule242382 struct {
	Client    client.Client
	Namespace string
	Logger    *slog.Logger
}

func (r *Rule242382) ID() string {
	return ID242382
}

func (r *Rule242382) Name() string {
	return "Kubernetes API Server must enable Node,RBAC as the authorization mode (MEDIUM 242382)"
}

func (r *Rule242382) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		kapiName = "kube-apiserver"
		option   = "authorization-mode"
	)
	target := rule.NewTarget("cluster", "seed", "name", kapiName, "namespace", r.Namespace, "kind", "deployment")

	optSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, kapiName, kapiName, r.Namespace, option)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	// option defaults to not allowed value AlwaysAllow
	switch {
	case len(optSlice) == 0:
		return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s has not been set.", option), target)), nil
	case len(optSlice) > 1:
		return rule.SingleCheckResult(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target)), nil
	case slices.Contains(strings.Split(optSlice[0], ","), "AlwaysAllow"):
		return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), target)), nil
	case utils.EqualSets([]string{"Node", "RBAC"}, strings.Split(optSlice[0], ",")):
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target)), nil
	default:
		return rule.SingleCheckResult(r, rule.WarningCheckResult(fmt.Sprintf("Option %s set to not recommended value.", option), target)), nil
	}
}
