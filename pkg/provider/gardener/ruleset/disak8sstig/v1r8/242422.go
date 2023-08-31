// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

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

var _ rule.Rule = &Rule242422{}

type Rule242422 struct {
	Client    client.Client
	Namespace string
	Logger    *slog.Logger
}

func (r *Rule242422) ID() string {
	return ID242422
}

func (r *Rule242422) Name() string {
	return "Kubernetes API Server must have a certificate for communication (MEDIUM 242422)"
}

func (r *Rule242422) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		kapiName    = "kube-apiserver"
		certOptName = "tls-cert-file"
		keyOptName  = "tls-private-key-file"
	)
	checkResults := []rule.CheckResult{}
	target := gardener.NewTarget("cluster", "seed", "name", kapiName, "namespace", r.Namespace, "kind", "deployment")

	tlsCertFileOptionSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, kapiName, kapiName, r.Namespace, certOptName)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	switch {
	case len(tlsCertFileOptionSlice) == 0:
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s has not been set.", certOptName), target))
	case len(tlsCertFileOptionSlice) > 1:
		checkResults = append(checkResults, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", certOptName), target))
	case strings.TrimSpace(tlsCertFileOptionSlice[0]) == "":
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s is empty.", certOptName), target))
	default:
		checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set.", certOptName), target))
	}

	tlsPrivateKeyFileOptionSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, kapiName, kapiName, r.Namespace, keyOptName)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	switch {
	case len(tlsPrivateKeyFileOptionSlice) == 0:
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s has not been set.", keyOptName), target))
	case len(tlsPrivateKeyFileOptionSlice) > 1:
		checkResults = append(checkResults, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", keyOptName), target))
	case strings.TrimSpace(tlsPrivateKeyFileOptionSlice[0]) == "":
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s is empty.", keyOptName), target))
	default:
		checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set.", keyOptName), target))
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
