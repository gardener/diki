// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/client-go/kubernetes/scheme"
	admissionapiv1 "k8s.io/pod-security-admission/admission/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule254800{}

type Rule254800 struct {
	Client    client.Client
	Namespace string
	Options   *Options254800
	Logger    *slog.Logger
}

type Options254800 struct {
	MinPodSecurityLevel string
}

func (r *Rule254800) ID() string {
	return ID254800
}

func (r *Rule254800) Name() string {
	return "Kubernetes must have a Pod Security Admission control file configured (HIGH 254800)"
}

func (r *Rule254800) Run(ctx context.Context) (rule.RuleResult, error) {
	target := gardener.NewTarget("cluster", "seed", "name", "kube-apiserver", "namespace", r.Namespace, "kind", "deployment")

	admissionControlConfigFileOptionSlice, err := utils.GetCommandOptionFromDeployment(ctx, r.Client, "kube-apiserver", "kube-apiserver", r.Namespace, "admission-control-config-file")
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if len(admissionControlConfigFileOptionSlice) == 0 {
		return rule.SingleCheckResult(r, rule.WarningCheckResult("Option admission-control-config-file has not been set.", target)), nil
	}

	if len(admissionControlConfigFileOptionSlice) > 1 {
		return rule.SingleCheckResult(r, rule.WarningCheckResult("Option admission-control-config-file has been set more than once in container command.", target)), nil
	}

	kubeAPIDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-apiserver",
			Namespace: r.Namespace,
		},
	}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(kubeAPIDeployment), kubeAPIDeployment); err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	volumePath := admissionControlConfigFileOptionSlice[0]

	admissionConfigByteSlice, err := kubeutils.GetVolumeConfigByteSliceByMountPath(ctx, r.Client, kubeAPIDeployment, "kube-apiserver", volumePath)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	admissionConfig := apiserverv1.AdmissionConfiguration{}
	_, _, err = serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer().Decode(admissionConfigByteSlice, nil, &admissionConfig)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if r.Options == nil {
		r.Options = &Options254800{
			MinPodSecurityLevel: "baseline",
		}
	}

	for _, plugin := range admissionConfig.Plugins {
		if plugin.Name == "PodSecurity" {
			if plugin.Configuration != nil {
				return rule.RuleResult{
					RuleID:       r.ID(),
					RuleName:     r.Name(),
					CheckResults: r.checkPodSecurityConfiguration(plugin.Configuration),
				}, nil
			}
			if strings.TrimSpace(plugin.Path) != "" {
				pluginAdmissionConfigByteSlice, err := kubeutils.GetVolumeConfigByteSliceByMountPath(ctx, r.Client, kubeAPIDeployment, "kube-apiserver", plugin.Path)
				if err != nil {
					return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
				}

				pluginConfig := admissionapiv1.PodSecurityConfiguration{}
				_, _, err = serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer().Decode(pluginAdmissionConfigByteSlice, nil, &pluginConfig)
				if err != nil {
					return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
				}

				return rule.RuleResult{
					RuleID:       r.ID(),
					RuleName:     r.Name(),
					CheckResults: r.checkPrivilegeLevel(pluginConfig),
				}, nil
			}
		}
	}

	return rule.SingleCheckResult(r, rule.FailedCheckResult("PodSecurity is not configured", gardener.NewTarget("cluster", "shoot"))), nil
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
		return []rule.CheckResult{rule.FailedCheckResult(err.Error(), gardener.NewTarget("cluster", "shoot"))}
	}

	return r.checkPrivilegeLevel(podSecurityConfig)
}

func (r *Rule254800) checkPrivilegeLevel(podSecurityConfig admissionapiv1.PodSecurityConfiguration) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
	target := gardener.NewTarget("cluster", "shoot", "kind", "PodSecurityConfiguration")
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
