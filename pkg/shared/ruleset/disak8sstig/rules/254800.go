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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/client-go/kubernetes/scheme"
	admissionapiv1 "k8s.io/pod-security-admission/admission/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ rule.Rule = &Rule254800{}
var _ rule.Severity = &Rule254800{}

type Rule254800 struct {
	Client         client.Client
	Namespace      string
	Options        *Options254800
	DeploymentName string
	ContainerName  string
}

type Options254800 struct {
	MinPodSecurityLevel string `json:"minPodSecurityLevel" yaml:"minPodSecurityLevel"`
}

var _ option.Option = (*Options254800)(nil)

func (o Options254800) Validate() field.ErrorList {
	if !slices.Contains([]string{"restricted", "baseline", "privileged"}, o.MinPodSecurityLevel) && len(o.MinPodSecurityLevel) > 0 {
		return field.ErrorList{field.Invalid(field.NewPath("minPodSecurityLevel"), o.MinPodSecurityLevel, "must be one of 'restricted', 'baseline' or 'privileged'")}
	}
	return nil
}

func (r *Rule254800) ID() string {
	return ID254800
}

func (r *Rule254800) Name() string {
	return "Kubernetes must have a Pod Security Admission control file configured."
}

func (r *Rule254800) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule254800) Run(ctx context.Context) (rule.RuleResult, error) {
	deploymentName := "kube-apiserver"
	containerName := "kube-apiserver"

	if r.DeploymentName != "" {
		deploymentName = r.DeploymentName
	}

	if r.ContainerName != "" {
		containerName = r.ContainerName
	}
	target := rule.NewTarget("name", deploymentName, "namespace", r.Namespace, "kind", "deployment")

	admissionControlConfigFileOptionSlice, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.Client, deploymentName, containerName, r.Namespace, "admission-control-config-file")
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if len(admissionControlConfigFileOptionSlice) == 0 {
		return rule.Result(r, rule.WarningCheckResult("Option admission-control-config-file has not been set.", target)), nil
	}

	if len(admissionControlConfigFileOptionSlice) > 1 {
		return rule.Result(r, rule.WarningCheckResult("Option admission-control-config-file has been set more than once in container command.", target)), nil
	}

	kubeAPIDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Namespace: r.Namespace,
		},
	}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(kubeAPIDeployment), kubeAPIDeployment); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	volumePath := admissionControlConfigFileOptionSlice[0]

	admissionConfigByteSlice, err := kubeutils.GetVolumeConfigByteSliceByMountPath(ctx, r.Client, kubeAPIDeployment, containerName, volumePath)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	admissionConfig := apiserverv1.AdmissionConfiguration{}
	_, _, err = serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer().Decode(admissionConfigByteSlice, nil, &admissionConfig)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if r.Options == nil {
		r.Options = &Options254800{
			MinPodSecurityLevel: "baseline",
		}
	}

	for _, plugin := range admissionConfig.Plugins {
		if plugin.Name == "PodSecurity" {
			if plugin.Configuration != nil {
				return rule.Result(r, r.checkPodSecurityConfiguration(plugin.Configuration)...), nil
			}
			if strings.TrimSpace(plugin.Path) != "" {
				pluginAdmissionConfigByteSlice, err := kubeutils.GetVolumeConfigByteSliceByMountPath(ctx, r.Client, kubeAPIDeployment, "kube-apiserver", plugin.Path)
				if err != nil {
					return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
				}

				pluginConfig := admissionapiv1.PodSecurityConfiguration{}
				_, _, err = serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer().Decode(pluginAdmissionConfigByteSlice, nil, &pluginConfig)
				if err != nil {
					return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
				}

				return rule.Result(r, r.checkPrivilegeLevel(pluginConfig)...), nil
			}
		}
	}

	return rule.Result(r, rule.FailedCheckResult("PodSecurity is not configured", rule.NewTarget())), nil
}

func privilegeLevel(privilege string) int {
	switch privilege {
	case "restricted":
		return 3
	case "baseline":
		return 2
	default:
		return 1
	}
}

func (r *Rule254800) checkPodSecurityConfiguration(pluginConfig *runtime.Unknown) []rule.CheckResult {
	podSecurityConfig := admissionapiv1.PodSecurityConfiguration{}
	if _, _, err := serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer().Decode(pluginConfig.Raw, nil, &podSecurityConfig); err != nil {
		return []rule.CheckResult{rule.FailedCheckResult(err.Error(), rule.NewTarget())}
	}

	return r.checkPrivilegeLevel(podSecurityConfig)
}

func (r *Rule254800) checkPrivilegeLevel(podSecurityConfig admissionapiv1.PodSecurityConfiguration) []rule.CheckResult {
	var checkResults []rule.CheckResult
	target := rule.NewTarget("kind", "PodSecurityConfiguration")
	if privilegeLevel(podSecurityConfig.Defaults.Enforce) < privilegeLevel(r.Options.MinPodSecurityLevel) {
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Enforce level is lower than the minimum pod security level allowed: %s", r.Options.MinPodSecurityLevel), target))
	}
	if privilegeLevel(podSecurityConfig.Defaults.Audit) < privilegeLevel(r.Options.MinPodSecurityLevel) {
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Audit level is lower than the minimum pod security level allowed: %s", r.Options.MinPodSecurityLevel), target))
	}
	if privilegeLevel(podSecurityConfig.Defaults.Warn) < privilegeLevel(r.Options.MinPodSecurityLevel) {
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Warn level is lower than the minimum pod security level allowed: %s", r.Options.MinPodSecurityLevel), target))
	}
	if len(checkResults) == 0 {
		checkResults = append(checkResults, rule.PassedCheckResult("PodSecurity is properly configured", target))
	}
	return checkResults
}
