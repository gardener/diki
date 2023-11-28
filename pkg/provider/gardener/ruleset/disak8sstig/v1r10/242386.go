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
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242386{}

type Rule242386 struct {
	Client    client.Client
	Namespace string
	Logger    *slog.Logger
}

func (r *Rule242386) ID() string {
	return ID242386
}

func (r *Rule242386) Name() string {
	return "Kubernetes API server must have the insecure port flag disabled (HIGH 242386)"
}

func (r *Rule242386) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		kapiName = "kube-apiserver"
		optName  = "insecure-port"
	)
	target := rule.NewTarget("cluster", "seed", "kind", "deployment", "name", kapiName, "namespace", r.Namespace)

	insecurePortOptionSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, kapiName, kapiName, r.Namespace, optName)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if len(insecurePortOptionSlice) == 0 {
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", optName), target)), nil
	}

	// insecure-port is deprecated but still needed for health checks. ref https://github.com/kubernetes/kubernetes/issues/43784
	return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set.", optName), target)), nil
}
