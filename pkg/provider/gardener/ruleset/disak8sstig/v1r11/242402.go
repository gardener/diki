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
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242402{}

type Rule242402 struct {
	Client    client.Client
	Namespace string
	Logger    *slog.Logger
}

func (r *Rule242402) ID() string {
	return ID242402
}

func (r *Rule242402) Name() string {
	return "Kubernetes API Server must have an audit log path set (MEDIUM 242402)"
}

func (r *Rule242402) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		kapiName = "kube-apiserver"
		option   = "audit-log-path"
	)
	target := gardener.NewTarget("cluster", "seed", "name", kapiName, "namespace", r.Namespace, "kind", "deployment")

	optSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, kapiName, kapiName, r.Namespace, option)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	// setting option is required
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
