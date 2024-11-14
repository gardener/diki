// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule242381{}
	_ rule.Severity = &Rule242381{}
)

type Rule242381 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
	ContainerName  string
}

func (r *Rule242381) ID() string {
	return ID242381
}

func (r *Rule242381) Name() string {
	return "The Kubernetes Controller Manager must create unique service accounts for each work payload."
}

func (r *Rule242381) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule242381) Run(ctx context.Context) (rule.RuleResult, error) {
	const option = "use-service-account-credentials"
	deploymentName := "kube-controller-manager"
	containerName := "kube-controller-manager"

	if r.DeploymentName != "" {
		deploymentName = r.DeploymentName
	}

	if r.ContainerName != "" {
		containerName = r.ContainerName
	}
	target := rule.NewTarget("name", deploymentName, "namespace", r.Namespace, "kind", "deployment")

	optSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, option)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	switch {
	case len(optSlice) == 0:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has not been set.", option), target)), nil
	case len(optSlice) > 1:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target)), nil
	case optSlice[0] == "false":
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), target)), nil
	case optSlice[0] == "true":
		return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target)), nil
	default:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s set to neither 'true' nor 'false'.", option), target)), nil
	}
}
