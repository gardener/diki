// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242419{}

type Rule242419 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
	ContainerName  string
}

func (r *Rule242419) ID() string {
	return ID242419
}

func (r *Rule242419) Name() string {
	return "Kubernetes API Server must have the SSL Certificate Authority set (MEDIUM 242419)"
}

func (r *Rule242419) Run(ctx context.Context) (rule.RuleResult, error) {
	const option = "client-ca-file"
	deploymentName := "kube-apiserver"
	containerName := "kube-apiserver"

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

	// setting option is required
	switch {
	case len(optSlice) == 0:
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s has not been set.", option), target)), nil
	case len(optSlice) > 1:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target)), nil
	case strings.TrimSpace(optSlice[0]) == "":
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s is empty.", option), target)), nil
	default:
		return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set.", option), target)), nil
	}
}