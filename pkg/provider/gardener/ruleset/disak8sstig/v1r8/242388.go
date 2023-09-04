// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"
	"fmt"
	"log/slog"

	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242388{}

type Rule242388 struct {
	Client    client.Client
	Namespace string
	Logger    *slog.Logger
}

func (r *Rule242388) ID() string {
	return ID242388
}

func (r *Rule242388) Name() string {
	return "Kubernetes API server must have the insecure bind address not set (HIGH 242388)"
}

func (r *Rule242388) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		kapiName = "kube-apiserver"
		optName  = "insecure-bind-address"
	)
	target := gardener.NewTarget("cluster", "seed", "kind", "deployment", "name", kapiName, "namespace", r.Namespace)

	insecureBindAddressOptionSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, kapiName, kapiName, r.Namespace, optName)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if len(insecureBindAddressOptionSlice) == 0 {
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", optName), target)), nil
	}

	// insecure-bind-address is deprecated but still needed for health checks. ref https://github.com/kubernetes/kubernetes/issues/43784
	return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set.", optName), target)), nil
}
