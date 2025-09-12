// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubectl/pkg/scheme"
	admissionapiv1 "k8s.io/pod-security-admission/admission/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	intkubeutils "github.com/gardener/diki/pkg/internal/kubernetes/utils"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule     = &Rule2007{}
	_ rule.Severity = &Rule2007{}
	_ option.Option = &Options2007{}
)

type Options2007 struct {
	MinPodSecurityStandardsProfile intkubeutils.PodSecurityStandardProfile `json:"minPodSecurityStandardsProfile" yaml:"minPodSecurityStandardsProfile"`
}

func (o Options2007) Validate(fldPath *field.Path) field.ErrorList {
	if !slices.Contains([]intkubeutils.PodSecurityStandardProfile{intkubeutils.PSSProfileBaseline, intkubeutils.PSSProfilePrivileged, intkubeutils.PSSProfileRestricted}, o.MinPodSecurityStandardsProfile) {
		return field.ErrorList{field.Invalid(fldPath.Child("minPodSecurityStandardsProfile"), o.MinPodSecurityStandardsProfile, "must be one of 'restricted', 'baseline' or 'privileged'")}
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
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), kubeutils.TargetWithK8sObject(rule.NewTarget(), metav1.TypeMeta{Kind: "Shoot"}, shoot.ObjectMeta))), nil
	}

	if shoot.Spec.Kubernetes.KubeAPIServer == nil || shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins == nil {
		return rule.Result(r, rule.FailedCheckResult("PodSecurity admission plugin is not configured.", rule.NewTarget())), nil
	}

	if slices.ContainsFunc(shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins, func(admissionPlugin gardencorev1beta1.AdmissionPlugin) bool {
		return admissionPlugin.Name == "PodSecurity" && admissionPlugin.Disabled != nil && *admissionPlugin.Disabled
	}) {
		return rule.Result(r, rule.FailedCheckResult("PodSecurity admission plugin is disabled.", rule.NewTarget())), nil
	}

	pluginIdx := slices.IndexFunc(shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins, func(admissionPlugin gardencorev1beta1.AdmissionPlugin) bool {
		return admissionPlugin.Name == "PodSecurity"
	})

	if pluginIdx < 0 || shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins[pluginIdx].Config == nil {
		return rule.Result(r, rule.FailedCheckResult("PodSecurity admission plugin is not configured.", rule.NewTarget())), nil
	}

	var (
		pluginConfiguration      = shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins[pluginIdx].Config
		podSecurityConfiguration = &admissionapiv1.PodSecurityConfiguration{}
	)

	if _, _, err := serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer().Decode(pluginConfiguration.Raw, nil, podSecurityConfiguration); err != nil {
		return rule.Result(r, rule.FailedCheckResult(err.Error(), rule.NewTarget())), nil
	}

	options := cmp.Or(r.Options, &Options2007{MinPodSecurityStandardsProfile: "baseline"})

	return rule.Result(r, r.evaluatePodSecurityConfigPrivileges(*podSecurityConfiguration, options)...), nil
}

func (r *Rule2007) evaluatePodSecurityConfigPrivileges(configuration admissionapiv1.PodSecurityConfiguration, options *Options2007) []rule.CheckResult {
	var checkResults []rule.CheckResult
	target := rule.NewTarget("kind", "PodSecurityConfiguration")

	if intkubeutils.PodSecurityStandardProfile(configuration.Defaults.Enforce).LessRestrictive(options.MinPodSecurityStandardsProfile) {
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Enforce mode profile is less restrictive than the minimum Pod Security Standards profile allowed: %s.", options.MinPodSecurityStandardsProfile), target))
	}
	if intkubeutils.PodSecurityStandardProfile(configuration.Defaults.Warn).LessRestrictive(options.MinPodSecurityStandardsProfile) {
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Warn mode profile is less restrictive than the minimum Pod Security Standards profile allowed: %s.", options.MinPodSecurityStandardsProfile), target))
	}
	if intkubeutils.PodSecurityStandardProfile(configuration.Defaults.Audit).LessRestrictive(options.MinPodSecurityStandardsProfile) {
		checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Audit mode profile is less restrictive than the minimum Pod Security Standards profile allowed: %s.", options.MinPodSecurityStandardsProfile), target))
	}

	if len(checkResults) == 0 {
		checkResults = append(checkResults, rule.PassedCheckResult("PodSecurity admission plugin is configured correctly.", rule.NewTarget()))
	}

	return checkResults
}
