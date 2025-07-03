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

var (
	_ rule.Rule     = &Rule245544{}
	_ rule.Severity = &Rule245544{}
)

type Rule245544 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
	ContainerName  string
}

func (r *Rule245544) ID() string {
	return ID245544
}

func (r *Rule245544) Name() string {
	return "Kubernetes endpoints must use approved organizational certificate and key pair to protect information in transit."
}

func (r *Rule245544) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule245544) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		certOptName = "kubelet-client-certificate"
		keyOptName  = "kubelet-client-key"
	)
	deploymentName := "kube-apiserver"
	containerName := "kube-apiserver"

	if r.DeploymentName != "" {
		deploymentName = r.DeploymentName
	}

	if r.ContainerName != "" {
		containerName = r.ContainerName
	}
	var checkResults []rule.CheckResult
	target := rule.NewTarget("name", deploymentName, "namespace", r.Namespace, "kind", "Deployment")

	kubeletClientCertificateOptionSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, certOptName)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	switch {
	case len(kubeletClientCertificateOptionSlice) == 0:
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s has not been set.", certOptName), target))
	case len(kubeletClientCertificateOptionSlice) > 1:
		checkResults = append(checkResults, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", certOptName), target))
	case strings.TrimSpace(kubeletClientCertificateOptionSlice[0]) == "":
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s is empty.", certOptName), target))
	default:
		checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set.", certOptName), target))
	}

	kubeletClientKeyOptionSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, keyOptName)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	switch {
	case len(kubeletClientKeyOptionSlice) == 0:
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s has not been set.", keyOptName), target))
	case len(kubeletClientKeyOptionSlice) > 1:
		checkResults = append(checkResults, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", keyOptName), target))
	case strings.TrimSpace(kubeletClientKeyOptionSlice[0]) == "":
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s is empty.", keyOptName), target))
	default:
		checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set.", keyOptName), target))
	}

	return rule.Result(r, checkResults...), nil
}
