// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
	disaoptions "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var (
	_ rule.Rule          = &Rule2003{}
	_ rule.Severity      = &Rule2003{}
	_ disaoptions.Option = &Options2003{}
)

type Options2003 struct {
	AcceptedPods []AcceptedPods2003 `json:"acceptedPods" yaml:"acceptedPods"`
}

type AcceptedPods2003 struct {
	option.AcceptedNamespacedObject
	VolumeNames []string `json:"volumeNames" yaml:"volumeNames"`
}

// Validate validates that option configurations are correctly defined
func (o Options2003) Validate() field.ErrorList {
	var (
		allErrs  field.ErrorList
		rootPath = field.NewPath("acceptedPods")
	)
	for _, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate()...)
		if len(p.VolumeNames) == 0 {
			allErrs = append(allErrs, field.Required(rootPath.Child("volumeNames"), "must not be empty"))
		}
		for i, volumeName := range p.VolumeNames {
			if len(volumeName) == 0 {
				allErrs = append(allErrs, field.Invalid(rootPath.Child("volumeNames").Index(i), volumeName, "must not be empty"))
			}
		}
	}
	return allErrs
}

type Rule2003 struct {
	Client  client.Client
	Options *Options2003
}

func (r *Rule2003) ID() string {
	return "2003"
}

func (r *Rule2003) Name() string {
	return "Pods should use only allowed volume types."
}

func (r *Rule2003) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule2003) Run(ctx context.Context) (rule.RuleResult, error) {
	allNamespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "namespaceList"))), nil
	}

	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList"))), nil
	}

	var checkResults []rule.CheckResult
	for _, pod := range pods {
		uses := false
		podTarget := rule.NewTarget("kind", "pod", "name", pod.Name, "namespace", pod.Namespace)
		for _, volume := range pod.Spec.Volumes {
			volumeTarget := podTarget.With("volume", volume.Name)
			if volume.ConfigMap == nil &&
				volume.CSI == nil &&
				volume.DownwardAPI == nil &&
				volume.EmptyDir == nil &&
				volume.Ephemeral == nil &&
				volume.PersistentVolumeClaim == nil &&
				volume.Projected == nil &&
				volume.Secret == nil {
				uses = true
				accepted, justification := r.accepted(volume, pod, allNamespaces[pod.Namespace])
				if accepted {
					checkResults = append(checkResults, rule.AcceptedCheckResult(justification, volumeTarget))
				} else {
					checkResults = append(checkResults, rule.FailedCheckResult("Pod uses not allowed volume type.", volumeTarget))
				}
			}
		}
		if !uses {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod uses only allowed volume types.", podTarget))
		}
	}
	return rule.Result(r, checkResults...), nil
}

func (r *Rule2003) accepted(volume corev1.Volume, pod corev1.Pod, namespace corev1.Namespace) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if utils.MatchLabels(pod.Labels, acceptedPod.MatchLabels) && utils.MatchLabels(namespace.Labels, acceptedPod.NamespaceMatchLabels) {
			if slices.Contains(acceptedPod.VolumeNames, "*") || slices.Contains(acceptedPod.VolumeNames, volume.Name) {
				return true, acceptedPod.Justification
			}
		}
	}

	return false, ""
}
