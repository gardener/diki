// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
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
	"k8s.io/apimachinery/pkg/util/validation/field"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var (
	_ rule.Rule     = &Rule242390{}
	_ rule.Severity = &Rule242390{}
	_ option.Option = &Options242390{}
)

type Rule242390 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
	ContainerName  string
	Options        *Options242390
}

type Options242390 struct {
	AllowedEndpoints []AllowedEndpoint `yaml:"allowedEndpoints" json:"allowedEndpoints"`
}

type AllowedEndpoint struct {
	Path string `yaml:"path" json:"path"`
}

func (o Options242390) Validate() field.ErrorList {
	var (
		allErrs              field.ErrorList
		allowedEndpointsPath = field.NewPath("allowedEndpoints")
	)

	if len(o.AllowedEndpoints) == 0 {
		return field.ErrorList{field.Required(allowedEndpointsPath, "must not be empty")}
	}

	for i, e := range o.AllowedEndpoints {
		if len(e.Path) == 0 {
			allErrs = append(allErrs, field.Required(allowedEndpointsPath.Index(i).Child("path"), "must not be empty"))
		}
	}

	return allErrs
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

		if r.Options == nil || len(authConfig.Anonymous.Conditions) == 0 {
			return rule.Result(r, rule.FailedCheckResult("The authentication configuration has anonymous authentication enabled.", target)), nil
		}

		var checkResults []rule.CheckResult

		for _, condition := range authConfig.Anonymous.Conditions {
			if !slices.ContainsFunc(r.Options.AllowedEndpoints, func(allowedPath AllowedEndpoint) bool {
				return allowedPath.Path == condition.Path
			}) {
				checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Anonymous authentication is not allowed for endpoint %s of the kube-apiserver.", condition.Path), target))
			}
		}

		if len(checkResults) == 0 {
			return rule.Result(r, rule.AcceptedCheckResult("The authentication configuration is allowed to have anonymous authentication enabled.", target)), nil
		}

		return rule.Result(r, checkResults...), nil
	default:
		return rule.Result(r, rule.PassedCheckResult("The authentication configuration has anonymous authentication disabled.", target)), nil
	}
}
