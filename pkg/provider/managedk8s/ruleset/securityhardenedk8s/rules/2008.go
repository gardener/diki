// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var (
	_ rule.Rule     = &Rule2008{}
	_ rule.Severity = &Rule2008{}
)

type Rule2008 struct {
	Client  client.Client
	Options *Options2008
}

type Options2008 struct {
	AcceptedPods []AcceptedPods2008 `json:"acceptedPods" yaml:"acceptedPods"`
}

var _ option.Option = (*Options2008)(nil)

type AcceptedPods2008 struct {
	option.PodSelector
	VolumeNames   []string `json:"volumeNames" yaml:"volumeNames"`
	Justification string   `json:"justification" yaml:"justification"`
}

// Validate validates that option configurations are correctly defined
func (o Options2008) Validate() field.ErrorList {
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
				allErrs = append(allErrs, field.Invalid(rootPath.Child("volumeNames").Index(i), volumeName, "must not be empty string"))
			}
		}
	}
	return allErrs
}

func (r *Rule2008) ID() string {
	return "2008"
}

func (r *Rule2008) Name() string {
	return "Pods must not be allowed to mount host directories."
}

func (r *Rule2008) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule2008) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults []rule.CheckResult
	)

	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList"))), nil
	}

	namespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "namespaceList"))), nil
	}

	for _, pod := range pods {
		podTarget := rule.NewTarget("kind", "pod", "name", pod.Name, "namespace", pod.Namespace)
		uses := false
		for _, volume := range pod.Spec.Volumes {
			volumeTarget := podTarget.With("volume", volume.Name)
			if volume.HostPath != nil {
				uses = true
				if accepted, justification := r.accepted(pod, namespaces[pod.Namespace], volume.Name); accepted {
					msg := "Pod accepted to use volume of type hostPath."
					if justification != "" {
						msg = justification
					}
					checkResults = append(checkResults, rule.AcceptedCheckResult(msg, volumeTarget))
				} else {
					checkResults = append(checkResults, rule.FailedCheckResult("Pod may not use volume of type hostPath.", volumeTarget))
				}
			}
		}
		if !uses {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not use volume of type hostPath.", podTarget))
		}
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule2008) accepted(pod corev1.Pod, namespace corev1.Namespace, volumeName string) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if utils.MatchLabels(pod.Labels, acceptedPod.PodMatchLabels) &&
			utils.MatchLabels(namespace.Labels, acceptedPod.NamespaceMatchLabels) {
			for _, acceptedVolumeName := range acceptedPod.VolumeNames {
				if acceptedVolumeName == volumeName {
					return true, acceptedPod.Justification
				}
			}
		}
	}

	return false, ""
}
