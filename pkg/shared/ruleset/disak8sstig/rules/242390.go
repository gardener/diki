// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule242390{}
	_ rule.Severity = &Rule242390{}
)

type Rule242390 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
	ContainerName  string
}

func (r *Rule242390) ID() string {
	return ID242390
}

func (r *Rule242390) Name() string {
	return "The Kubernetes API server must have anonymous authentication disabled."
}

func (r *Rule242390) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule242390) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		anonymousAuthOption        = "anonymous-auth"
		authenticationConfigOption = "authentication-config"
	)

	deploymentName := "kube-apiserver"
	containerName := "kube-apiserver"

	if r.DeploymentName != "" {
		deploymentName = r.DeploymentName
	}

	if r.ContainerName != "" {
		containerName = r.ContainerName
	}
	target := rule.NewTarget("name", deploymentName, "namespace", r.Namespace, "kind", "Deployment")

	optSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, anonymousAuthOption)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if len(optSlice) > 0 {
		switch {
		case len(optSlice) > 1:
			return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", anonymousAuthOption), target)), nil
		case optSlice[0] == "true":
			return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", anonymousAuthOption), target)), nil
		case optSlice[0] == "false":
			return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", anonymousAuthOption), target)), nil
		default:
			return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s set to neither 'true' nor 'false'.", anonymousAuthOption), target)), nil
		}
	}

	optSlice, err = kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, authenticationConfigOption)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if len(optSlice) == 0 {
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Neither options %s nor %s have been set.", anonymousAuthOption, authenticationConfigOption), target)), nil
	}

	if len(optSlice) > 1 {
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", authenticationConfigOption), target)), nil
	}

	kubeAPIServerDeployment := &appsv1.Deployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      deploymentName,
			Namespace: r.Namespace,
		},
	}

	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(kubeAPIServerDeployment), kubeAPIServerDeployment); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	bytes, err := kubeutils.GetVolumeConfigByteSliceByMountPath(ctx, r.Client, kubeAPIServerDeployment, containerName, optSlice[0])
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	authConfig := &apiserverv1beta1.AuthenticationConfiguration{}
	if err := yaml.Unmarshal(bytes, authConfig); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	switch {
	case authConfig.Anonymous == nil:
		return rule.Result(r, rule.FailedCheckResult("The authentication configuration does not explicitly disable anonymous authentication.", target)), nil
	case authConfig.Anonymous != nil && authConfig.Anonymous.Enabled:
		return rule.Result(r, rule.FailedCheckResult("The authentication configuration has anonymous authentication enabled.", target)), nil
	default:
		return rule.Result(r, rule.PassedCheckResult("The authentication configuration has anonymous authentication disabled.", target)), nil
	}
}
