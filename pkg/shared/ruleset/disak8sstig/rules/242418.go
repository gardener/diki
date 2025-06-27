// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule242418{}
	_ rule.Severity = &Rule242418{}
)

type Rule242418 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
	ContainerName  string
}

func (r *Rule242418) ID() string {
	return ID242418
}

func (r *Rule242418) Name() string {
	return "The Kubernetes API server must use approved cipher suites."
}

func (r *Rule242418) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242418) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		option         = "tls-cipher-suites"
		deploymentName = "kube-apiserver"
		containerName  = "kube-apiserver"
	)

	if r.DeploymentName != "" {
		deploymentName = r.DeploymentName
	}

	if r.ContainerName != "" {
		containerName = r.ContainerName
	}
	target := rule.NewTarget("name", deploymentName, "namespace", r.Namespace, "kind", "Deployment")

	optSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, option)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if len(optSlice) == 0 {
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has not been set.", option), target)), nil
	}

	if len(optSlice) > 1 {
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target)), nil
	}

	var (
		ciphers         = strings.Split(optSlice[0], ",")
		requiredCiphers = []string{
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		}
		unallowedCiphers = []string{
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		}
	)

	for _, suite := range tls.InsecureCipherSuites() {
		unallowedCiphers = append(unallowedCiphers, suite.Name)
	}

	if utils.Subset(requiredCiphers, ciphers) && !utils.Intersect(unallowedCiphers, ciphers) {
		return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed values.", option), target)), nil
	}

	return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed values.", option), target)), nil
}
