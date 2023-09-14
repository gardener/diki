// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242464{}

type Rule242464 struct {
	Client    client.Client
	Namespace string
	Logger    *slog.Logger
}

func (r *Rule242464) ID() string {
	return ID242464
}

func (r *Rule242464) Name() string {
	return "Kubernetes API Server audit log retention must be set (MEDIUM 242464)"
}

func (r *Rule242464) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		kapiName = "kube-apiserver"
		option   = "audit-log-maxage"
	)
	target := gardener.NewTarget("cluster", "seed", "name", kapiName, "namespace", r.Namespace, "kind", "deployment")

	optSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, kapiName, kapiName, r.Namespace, option)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if len(optSlice) == 0 {
		return rule.SingleCheckResult(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has not been set.", option), target)), nil
	}

	if len(optSlice) > 1 {
		return rule.SingleCheckResult(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target)), nil
	}

	auditLogMaxAge, err := strconv.ParseInt(optSlice[0], 10, 0)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if auditLogMaxAge < 30 {
		return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), target)), nil
	}

	return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target)), nil
}
