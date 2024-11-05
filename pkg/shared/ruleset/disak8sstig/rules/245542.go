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

var _ rule.Rule = &Rule245542{}

type Rule245542 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
	ContainerName  string
}

func (r *Rule245542) ID() string {
	return ID245542
}

func (r *Rule245542) Name() string {
	return "Kubernetes API Server must disable basic authentication to protect information in transit (HIGH 245542)"
}

func (r *Rule245542) Run(ctx context.Context) (rule.RuleResult, error) {
	const optName = "basic-auth-file"
	deploymentName := "kube-apiserver"
	containerName := "kube-apiserver"

	if r.DeploymentName != "" {
		deploymentName = r.DeploymentName
	}

	if r.ContainerName != "" {
		containerName = r.ContainerName
	}
	target := rule.NewTarget("name", deploymentName, "namespace", r.Namespace, "kind", "deployment")

	basicAuthFileOptionSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, optName)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	// empty options are required
	if len(basicAuthFileOptionSlice) == 0 {
		return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s has not been set.", optName), target)), nil
	}

	return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set.", optName), target)), nil
}
