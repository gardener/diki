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

// TODO (georgibaltiev): Remove the implementation of this rule once support for DISA STIG version v2r4 has been dropped.
var (
	_ rule.Rule     = &Rule242388{}
	_ rule.Severity = &Rule242388{}
)

type Rule242388 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
	ContainerName  string
}

func (r *Rule242388) ID() string {
	return ID242388
}

func (r *Rule242388) Name() string {
	return "The Kubernetes API server must have the insecure bind address not set."
}

func (r *Rule242388) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule242388) Run(ctx context.Context) (rule.RuleResult, error) {
	const optName = "insecure-bind-address"
	deploymentName := "kube-apiserver"
	containerName := "kube-apiserver"

	if r.DeploymentName != "" {
		deploymentName = r.DeploymentName
	}

	if r.ContainerName != "" {
		containerName = r.ContainerName
	}
	target := rule.NewTarget("kind", "Deployment", "name", deploymentName, "namespace", r.Namespace)

	insecureBindAddressOptionSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, optName)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if len(insecureBindAddressOptionSlice) == 0 {
		return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", optName), target)), nil
	}

	// insecure-bind-address is deprecated but still needed for health checks. ref https://github.com/kubernetes/kubernetes/issues/43784
	return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set.", optName), target)), nil
}
