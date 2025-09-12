// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"context"
	"slices"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	kubepod "github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
	disaoptions "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var (
	_ rule.Rule          = &Rule2008{}
	_ rule.Severity      = &Rule2008{}
	_ disaoptions.Option = &Options2008{}
)

type Rule2008 struct {
	Client  client.Client
	Options *Options2008
}

type Options2008 struct {
	AcceptedPods []AcceptedPods2008 `json:"acceptedPods" yaml:"acceptedPods"`
}

type AcceptedPods2008 struct {
	option.NamespacedObjectSelector
	VolumeNames   []string `json:"volumeNames" yaml:"volumeNames"`
	Justification string   `json:"justification" yaml:"justification"`
}

// Validate validates that option configurations are correctly defined.
func (o Options2008) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs          field.ErrorList
		acceptedPodsPath = fldPath.Child("acceptedPods")
	)
	for pIdx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(pIdx))...)
		if len(p.VolumeNames) == 0 {
			allErrs = append(allErrs, field.Required(acceptedPodsPath.Index(pIdx).Child("volumeNames"), "must not be empty"))
		}
		for vIdx, volumeName := range p.VolumeNames {
			if len(volumeName) == 0 {
				allErrs = append(allErrs, field.Invalid(acceptedPodsPath.Index(pIdx).Child("volumeNames").Index(vIdx), volumeName, "must not be empty"))
			}
		}
	}
	return allErrs
}

func (r *Rule2008) ID() string {
	return "2008"
}

func (r *Rule2008) Name() string {
	return "Pods must not mount host directories."
}

func (r *Rule2008) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule2008) Run(ctx context.Context) (rule.RuleResult, error) {
	var checkResults []rule.CheckResult

	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "PodList"))), nil
	}

	if len(pods) == 0 {
		return rule.Result(r, rule.PassedCheckResult("The cluster does not have any Pods.", rule.NewTarget())), nil
	}

	filteredPods := kubeutils.FilterPodsByOwnerRef(pods)

	namespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "NamespaceList"))), nil
	}

	replicaSets, err := kubeutils.GetReplicaSets(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "ReplicaSetList"))), nil
	}

	for _, pod := range filteredPods {
		var (
			uses                    = false
			podTarget               = kubeutils.TargetWithPod(rule.NewTarget(), pod, replicaSets)
			dikiPrivilegedPodLabels = map[string]string{
				kubepod.LabelComplianceRoleKey: kubepod.LabelComplianceRolePrivPod,
			}
		)

		// Diki privileged pod uses hostPath volume. During execution, parallel diki rules might create pods.
		if utils.MatchLabels(pod.Labels, dikiPrivilegedPodLabels) {
			checkResults = append(checkResults, rule.SkippedCheckResult("Diki privileged pod requires the use of hostPaths.", podTarget))
			continue
		}

		for _, volume := range pod.Spec.Volumes {
			volumeTarget := podTarget.With("volume", volume.Name)
			if volume.HostPath != nil {
				uses = true
				if accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels, volume.Name); err != nil {
					return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), err
				} else if accepted {
					msg := cmp.Or(justification, "Pod accepted to use volume of type hostPath.")
					checkResults = append(checkResults, rule.AcceptedCheckResult(msg, volumeTarget))
				} else {
					checkResults = append(checkResults, rule.FailedCheckResult("Pod must not use volumes of type hostPath.", volumeTarget))
				}
			}
		}
		if !uses {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not use volumes of type hostPath.", podTarget))
		}
	}
	return rule.Result(r, checkResults...), nil
}

func (r *Rule2008) accepted(podLabels, namespaceLabels map[string]string, volumeName string) (bool, string, error) {
	if r.Options == nil {
		return false, "", nil
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if matches, err := acceptedPod.Matches(podLabels, namespaceLabels); err != nil {
			return false, "", err
		} else if matches && (slices.Contains(acceptedPod.VolumeNames, "*") || slices.Contains(acceptedPod.VolumeNames, volumeName)) {
			return true, acceptedPod.Justification, nil
		}
	}

	return false, "", nil
}
