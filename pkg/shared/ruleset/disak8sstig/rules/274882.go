// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule274882{}
	_ rule.Severity = &Rule274882{}
)

type Rule274882 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
	ContainerName  string
}

func (r *Rule274882) ID() string {
	return ID274882
}

func (r *Rule274882) Name() string {
	return "The Kubernetes API server must have anonymous authentication disabled."
}

func (r *Rule274882) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule274882) Run(ctx context.Context) (rule.RuleResult, error) {

	const encryptionProviderConfigOption = "encryption-provider-config"

	deploymentName := "kube-apiserver"
	containerName := "kube-apiserver"

	if r.DeploymentName != "" {
		deploymentName = r.DeploymentName
	}

	if r.ContainerName != "" {
		containerName = r.ContainerName
	}

	target := rule.NewTarget("name", deploymentName, "namespace", r.Namespace, "kind", "Deployment")

	optSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, encryptionProviderConfigOption)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if len(optSlice) > 1 {
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in the container command.", encryptionProviderConfigOption), target)), nil
	} else if len(optSlice) == 0 {
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s has not been set in the container command.", encryptionProviderConfigOption), target)), nil
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

	encryptionProviderConfig := &apiserverv1.EncryptionConfiguration{}
	if err := yaml.Unmarshal(bytes, encryptionProviderConfig); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if len(encryptionProviderConfig.Resources) == 0 {
		return rule.Result(r, rule.FailedCheckResult("Secrets are not explicitly encrypted at REST.", target)), nil
	}

	for _, resourceConfig := range encryptionProviderConfig.Resources {
		if slices.ContainsFunc(resourceConfig.Resources, func(resourceName string) bool {
			return resourceName == "*." || resourceName == "*.*" || resourceName == "secrets"
		}) {
			if len(resourceConfig.Providers) == 0 {
				return rule.Result(r, rule.FailedCheckResult("Secrets are not explicitly encrypted at REST.", target)), nil
			}

			if resourceConfig.Providers[0].Identity != nil {
				return rule.Result(r, rule.FailedCheckResult("Secrets are explicitly stored as plain text.", target)), nil
			}

			return rule.Result(r, rule.PassedCheckResult("Secrets are encrypted at REST.", target)), nil
		}
	}

	return rule.Result(r, rule.FailedCheckResult("Secrets are not explicitly encrypted at REST.", target)), nil
}
