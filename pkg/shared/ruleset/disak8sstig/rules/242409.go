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
	_ rule.Rule     = &Rule242409{}
	_ rule.Severity = &Rule242409{}
)

type Rule242409 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
	ContainerName  string
}

func (r *Rule242409) ID() string {
	return ID242409
}

func (r *Rule242409) Name() string {
	return "Kubernetes Controller Manager must disable profiling."
}

func (r *Rule242409) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242409) Run(ctx context.Context) (rule.RuleResult, error) {
	const option = "profiling"
	deploymentName := "kube-controller-manager"
	containerName := "kube-controller-manager"

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

	switch {
	case len(optSlice) == 0:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has not been set.", option), target)), nil
	case len(optSlice) > 1:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target)), nil
	case optSlice[0] == "true":
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), target)), nil
	case optSlice[0] == "false":
		return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target)), nil
	default:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s set to neither 'true' nor 'false'.", option), target)), nil
	}
}
