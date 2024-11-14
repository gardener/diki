// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"strconv"

	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule242462{}
	_ rule.Severity = &Rule242462{}
)

type Rule242462 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
	ContainerName  string
}

func (r *Rule242462) ID() string {
	return ID242462
}

func (r *Rule242462) Name() string {
	return "The Kubernetes API Server must be set to audit log max size."
}

func (r *Rule242462) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242462) Run(ctx context.Context) (rule.RuleResult, error) {
	const option = "audit-log-maxsize"
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

	if len(optSlice) == 0 {
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has not been set.", option), target)), nil
	}

	if len(optSlice) > 1 {
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target)), nil
	}

	auditLogMaxSize, err := strconv.ParseInt(optSlice[0], 10, 0)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if auditLogMaxSize < 100 {
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), target)), nil
	}

	return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target)), nil
}
