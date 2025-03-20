// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule242436{}
	_ rule.Severity = &Rule242436{}
)

type Rule242436 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
	ContainerName  string
}

func (r *Rule242436) ID() string {
	return ID242436
}

func (r *Rule242436) Name() string {
	return "The Kubernetes API server must have the ValidatingAdmissionWebhook enabled."
}

func (r *Rule242436) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule242436) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		enableAdmissionPlugins  = "enable-admission-plugins"
		disableAdmissionPlugins = "disable-admission-plugins"
	)
	deploymentName := "kube-apiserver"
	containerName := "kube-apiserver"

	if r.DeploymentName != "" {
		deploymentName = r.DeploymentName
	}

	if r.ContainerName != "" {
		containerName = r.ContainerName
	}
	target := rule.NewTarget("name", deploymentName, "namespace", r.Namespace, "kind", "deployment")

	disableAdmissionPluginsSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, disableAdmissionPlugins)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if len(disableAdmissionPluginsSlice) > 1 {
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", disableAdmissionPlugins), target)), nil
	}
	if len(disableAdmissionPluginsSlice) == 1 && slices.Contains(strings.Split(disableAdmissionPluginsSlice[0], ","), "ValidatingAdmissionWebhook") {
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", disableAdmissionPlugins), target)), nil
	}

	enableAdmissionPluginsSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, enableAdmissionPlugins)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	// enable-admission-plugins defaults to allowed value ValidatingAdmissionWebhook
	// see https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/
	switch {
	case len(enableAdmissionPluginsSlice) == 0:
		return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s has not been set.", enableAdmissionPlugins), target)), nil
	case len(enableAdmissionPluginsSlice) > 1:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", enableAdmissionPlugins), target)), nil
	case slices.Contains(strings.Split(enableAdmissionPluginsSlice[0], ","), "ValidatingAdmissionWebhook"):
		return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", enableAdmissionPlugins), target)), nil
	default:
		return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s defaults to allowed value.", enableAdmissionPlugins), target)), nil
	}
}
