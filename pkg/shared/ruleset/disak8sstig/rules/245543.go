// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule     = &Rule245543{}
	_ rule.Severity = &Rule245543{}
)

type Rule245543 struct {
	Client         client.Client
	Namespace      string
	Options        *Options245543
	DeploymentName string
	ContainerName  string
}

type Options245543 struct {
	AcceptedTokens []struct {
		User   string `yaml:"user"`
		UID    string `yaml:"uid"`
		Groups string `yaml:"groups"`
	}
}

var _ option.Option = (*Options245543)(nil)

func (o Options245543) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList
	for idx, acceptedToken := range o.AcceptedTokens {
		if len(acceptedToken.User) == 0 {
			allErrs = append(allErrs, field.Required(fldPath.Child("acceptedTokens").Index(idx).Child("user"), "must be set"))
		}
		if len(acceptedToken.UID) == 0 {
			allErrs = append(allErrs, field.Required(fldPath.Child("acceptedTokens").Index(idx).Child("uid"), "must be set"))
		}
	}
	return allErrs
}

func (r *Rule245543) ID() string {
	return ID245543
}

func (r *Rule245543) Name() string {
	return "Kubernetes API Server must disable token authentication to protect information in transit."
}

func (r *Rule245543) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule245543) Run(ctx context.Context) (rule.RuleResult, error) {
	const option = "token-auth-file"
	deploymentName := "kube-apiserver"
	containerName := "kube-apiserver"

	if r.DeploymentName != "" {
		deploymentName = r.DeploymentName
	}

	if r.ContainerName != "" {
		containerName = r.ContainerName
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Namespace: r.Namespace,
		},
	}

	target := kubeutils.TargetWithK8sObject(rule.NewTarget(), metav1.TypeMeta{Kind: "Deployment"}, deployment.ObjectMeta)

	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(deployment), deployment); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	optSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, option)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if r.Options == nil {
		if len(optSlice) == 0 {
			return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s has not been set.", option), target)), nil
		}

		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s is set.", option), target)), nil
	}

	if len(optSlice) > 1 {
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target)), nil
	}

	optionByteSlice, err := kubeutils.GetVolumeConfigByteSliceByMountPath(ctx, r.Client, deployment, containerName, optSlice[0])
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	optionString := string(optionByteSlice)
	optionStringArray := strings.Split(optionString, "\n")
	tokens := make([][]string, 0, len(optionStringArray))
	for _, optionStringLine := range optionStringArray {
		token := strings.SplitN(optionStringLine, ",", 4)
		token[0] = "***"

		if len(token) < 3 {
			return rule.Result(r, rule.FailedCheckResult("Invalid token.", target)), nil
		}

		// we append an empty string in the end,
		// because isTokenAccepted expects 4 element array
		if len(token) == 3 {
			token = append(token, "")
		}

		// we strip " if present in both ends,
		// because isTokenAccepted does not expect them
		trimmedGroups := strings.TrimSpace(token[3])
		if len(trimmedGroups) >= 2 && trimmedGroups[0] == '"' && trimmedGroups[len(trimmedGroups)-1] == '"' {
			token[3] = trimmedGroups[1 : len(trimmedGroups)-1]
		}
		tokens = append(tokens, token)
	}

	for _, token := range tokens {
		if !r.isTokenAccepted([4]string(token)) {
			return rule.Result(r, rule.FailedCheckResult("Invalid token.", target)), nil
		}
	}

	return rule.Result(r, rule.AcceptedCheckResult("All defined tokens are accepted.", target)), nil
}

func (r *Rule245543) isTokenAccepted(token [4]string) bool {
	for _, acceptedToken := range r.Options.AcceptedTokens {
		if token[1] == acceptedToken.User && token[2] == acceptedToken.UID && token[3] == acceptedToken.Groups {
			return true
		}
	}

	return false
}
