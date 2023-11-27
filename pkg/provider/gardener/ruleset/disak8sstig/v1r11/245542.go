// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"log/slog"

	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule245542{}

type Rule245542 struct {
	Client    client.Client
	Namespace string
	Logger    *slog.Logger
}

func (r *Rule245542) ID() string {
	return ID245542
}

func (r *Rule245542) Name() string {
	return "Kubernetes API Server must disable basic authentication to protect information in transit (HIGH 245542)"
}

func (r *Rule245542) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		kapiName = "kube-apiserver"
		optName  = "basic-auth-file"
	)
	target := gardener.NewTarget("cluster", "seed", "name", kapiName, "namespace", r.Namespace, "kind", "deployment")

	basicAuthFileOptionSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, kapiName, kapiName, r.Namespace, optName)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	// empty options are required
	if len(basicAuthFileOptionSlice) == 0 {
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s has not been set.", optName), target)), nil
	}

	return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set.", optName), target)), nil
}
