// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242382{}

type Rule242382 struct {
	Client               client.Client
	Namespace            string
	DeploymentName       string
	ContainerName        string
	ExpectedInitialModes []string
}

func (r *Rule242382) ID() string {
	return ID242382
}

func (r *Rule242382) Name() string {
	return "The Kubernetes API Server must enable Node,RBAC as the authorization mode (MEDIUM 242382)"
}

func (r *Rule242382) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		authorizationModeOpt   = "authorization-mode"
		authorizationConfigOpt = "authorization-config"
	)
	var (
		deploymentName       = "kube-apiserver"
		containerName        = "kube-apiserver"
		expectedInitialModes = []string{"Node", "RBAC"}
	)

	if r.DeploymentName != "" {
		deploymentName = r.DeploymentName
	}

	if r.ContainerName != "" {
		containerName = r.ContainerName
	}

	if len(r.ExpectedInitialModes) != 0 {
		expectedInitialModes = r.ExpectedInitialModes
	}

	target := rule.NewTarget("name", deploymentName, "namespace", r.Namespace, "kind", "deployment")

	authzConfigOptSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, authorizationConfigOpt)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	switch {
	case len(authzConfigOptSlice) > 1:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", authorizationConfigOpt), target)), nil
	case len(authzConfigOptSlice) == 1 && strings.TrimSpace(authzConfigOptSlice[0]) == "":
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s is empty.", authorizationConfigOpt), target)), nil
	case len(authzConfigOptSlice) == 1:
		return r.checkAuthzConfig(ctx, deploymentName, containerName, authzConfigOptSlice[0], expectedInitialModes), nil
	default:
	}

	authzModeOptSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, authorizationModeOpt)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	// option defaults to not allowed value AlwaysAllow
	switch {
	case len(authzModeOptSlice) == 0:
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s has not been set.", authorizationModeOpt), target)), nil
	case len(authzModeOptSlice) > 1:
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", authorizationModeOpt), target)), nil
	case slices.Contains(strings.Split(authzModeOptSlice[0], ","), "AlwaysAllow"):
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", authorizationModeOpt), target)), nil
	case utils.InitialSegment(expectedInitialModes, strings.Split(authzModeOptSlice[0], ",")):
		return rule.Result(r, rule.PassedCheckResult(fmt.Sprintf("Option %s set to expected value.", authorizationModeOpt), target)), nil
	default:
		return rule.Result(r, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not expected value.", authorizationModeOpt), target)), nil
	}
}

func (r *Rule242382) checkAuthzConfig(ctx context.Context, deploymentName, containerName, volumePath string, expectedModes []string) rule.RuleResult {
	deploymentTarget := rule.NewTarget("name", deploymentName, "namespace", r.Namespace, "kind", "deployment")
	authzConfigTarget := rule.NewTarget("kind", "AuthorizationConfiguration")

	kubeAPIDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Namespace: r.Namespace,
		},
	}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(kubeAPIDeployment), kubeAPIDeployment); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), deploymentTarget))
	}

	authorizationConfigByteSlice, err := kubeutils.GetVolumeConfigByteSliceByMountPath(ctx, r.Client, kubeAPIDeployment, containerName, volumePath)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), deploymentTarget))
	}

	authorizationConfig := apiserverv1beta1.AuthorizationConfiguration{}
	_, _, err = serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer().Decode(authorizationConfigByteSlice, nil, &authorizationConfig)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), authzConfigTarget))
	}

	var modes []string
	for _, authorizer := range authorizationConfig.Authorizers {
		if authorizer.Type == "AlwaysAllow" {
			return rule.Result(r, rule.FailedCheckResult("AuthorizationConfiguration has not allowed mode type set.", authzConfigTarget))
		}
		modes = append(modes, authorizer.Type)
	}

	if utils.InitialSegment(expectedModes, modes) {
		return rule.Result(r, rule.PassedCheckResult("AuthorizationConfiguration has expected initial mode types set.", authzConfigTarget))
	}

	return rule.Result(r, rule.FailedCheckResult("AuthorizationConfiguration has not expected initial mode type set.", authzConfigTarget))
}
