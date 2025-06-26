// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"

	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule242378{}
	_ rule.Severity = &Rule242378{}
)

type Rule242378 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
	ContainerName  string
}

func (r *Rule242378) ID() string {
	return ID242378
}

func (r *Rule242378) Name() string {
	return "The Kubernetes API Server must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination."
}

func (r *Rule242378) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242378) Run(ctx context.Context) (rule.RuleResult, error) {
	const option = "tls-min-version"

	deploymentName := "kube-apiserver"
	containerName := "kube-apiserver"

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

	// empty options are allowed because min version defaults to TLS 1.2
	switch {
	case len(optSlice) == 0:
		return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s has not been set.", option), target)), nil
	case len(optSlice) > 1:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target)), nil
	case slices.Contains([]string{"VersionTLS10", "VersionTLS11"}, optSlice[0]):
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), target)), nil
	case slices.Contains([]string{"VersionTLS12", "VersionTLS13"}, optSlice[0]):
		return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target)), nil
	default:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set to unknown value.", option), target)), nil
	}
}
