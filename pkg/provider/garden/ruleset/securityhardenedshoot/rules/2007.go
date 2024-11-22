// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubectl/pkg/scheme"
	admissionapiv1 "k8s.io/pod-security-admission/admission/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	_ rule.Rule     = &Rule2007{}
	_ rule.Severity = &Rule2007{}
	_ option.Option = &Options2007{}
)

type Options2007 struct {
	MinPodSecurityLevel string `json:"minPodSecurityLevel" yaml:"minPodSecurityLevel"`
}

func (o *Options2007) Validate() field.ErrorList {
	if slices.Contains([]string{"restricted", "baseline", "privileged"}, o.MinPodSecurityLevel) && len(o.MinPodSecurityLevel) > 0 {
		return field.ErrorList{field.Invalid(field.NewPath("minPodSecurityLevel"), o.MinPodSecurityLevel, "must be one of 'restricted', 'baseline' or 'privileged'")}
	}
	return nil
}

type Rule2007 struct {
	Client         client.Client
	Options        *Options2007
	ShootName      string
	ShootNamespace string
}

func (r *Rule2007) ID() string {
	return "2007"
}

func (r *Rule2007) Name() string {
	return "Shoot clusters must have a PodSecurity admission plugin configured."
}

func (r *Rule2007) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule2007) Run(ctx context.Context) (rule.RuleResult, error) {
	shoot := &gardencorev1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", r.ShootName, "namespace", r.ShootNamespace, "kind", "Shoot"))), nil
	}

	var (
		podSecurityPlugin = "PodSecurity"
		privilegeLevel    = func(privilege string) int {
			switch {
			case privilege == "privileged" || privilege == "":
				return 1
			case privilege == "baseline":
				return 2
			default:
				return 3
			}
		}
	)

	if shoot.Spec.Kubernetes.KubeAPIServer == nil || shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins == nil {
		return rule.Result(r, rule.FailedCheckResult("The PodSecurity admission plugin is not configured.", rule.NewTarget())), nil
	}

	if slices.ContainsFunc(shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins, func(admissionPlugin gardencorev1beta1.AdmissionPlugin) bool {
		return admissionPlugin.Name == podSecurityPlugin && admissionPlugin.Disabled != nil && *admissionPlugin.Disabled
	}) {
		return rule.Result(r, rule.FailedCheckResult("The PodSecurity admission plugin is disabled.", rule.NewTarget())), nil
	}

	enabledPodSecurityPluginIdx := slices.IndexFunc(shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins, func(admissionPlugin gardencorev1beta1.AdmissionPlugin) bool {
		return admissionPlugin.Name == podSecurityPlugin
	})

	if enabledPodSecurityPluginIdx < 0 {
		return rule.Result(r, rule.FailedCheckResult("The PodSecurity admission plugin is not configured.", rule.NewTarget())), nil
	}

	var pluginConfiguration = shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins[enabledPodSecurityPluginIdx].Config

	if pluginConfiguration == nil {
		return rule.Result(r, rule.FailedCheckResult("The PodSecurity admission plugin has default privileges.", rule.NewTarget())), nil
	}

	podSecurityConfiguration := &admissionapiv1.PodSecurityConfiguration{}
	if _, _, err := serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer().Decode(pluginConfiguration.Raw, nil, podSecurityConfiguration); err != nil {
		return rule.Result(r, rule.FailedCheckResult(err.Error(), rule.NewTarget())), nil
	}

	if r.Options == nil {
		r.Options = &Options2007{
			MinPodSecurityLevel: "baseline",
		}
	}

	if privilegeLevel(podSecurityConfiguration.Defaults.Enforce) < privilegeLevel(r.Options.MinPodSecurityLevel) ||
		privilegeLevel(podSecurityConfiguration.Defaults.Warn) < privilegeLevel(r.Options.MinPodSecurityLevel) ||
		privilegeLevel(podSecurityConfiguration.Defaults.Audit) < privilegeLevel(r.Options.MinPodSecurityLevel) {
		return rule.Result(r, rule.FailedCheckResult("The PodSecurity admission has default privileges set.", rule.NewTarget())), nil
	}

	return rule.Result(r, rule.PassedCheckResult("PodSecurity admission plugin is configured correctly", rule.NewTarget())), nil
}
