// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242418{}

type Rule242418 struct {
	Client    client.Client
	Namespace string
	Logger    *slog.Logger
}

func (r *Rule242418) ID() string {
	return ID242418
}

func (r *Rule242418) Name() string {
	return "Kubernetes API server must use approved cipher suites (MEDIUM 242418)"
}

func (r *Rule242418) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		kapiName = "kube-apiserver"
		option   = "tls-cipher-suites"
	)
	target := rule.NewTarget("cluster", "seed", "name", kapiName, "namespace", r.Namespace, "kind", "deployment")

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

	ciphers := strings.Split(optSlice[0], ",")
	requiredCiphers := []string{
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	}

	if utils.Subset(requiredCiphers, ciphers) {
		return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed values.", option), target)), nil
	}

	return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed values.", option), target)), nil
}
