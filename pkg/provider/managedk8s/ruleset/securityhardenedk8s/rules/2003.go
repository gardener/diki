// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	kubepod "github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule     = &Rule2003{}
	_ rule.Severity = &Rule2003{}
	_ option.Option = &Options2003{}
)

type Options2003 struct {
	AcceptedPods []option.AcceptedPodVolumes `json:"acceptedPods" yaml:"acceptedPods"`
}

// Validate validates that option configurations are correctly defined.
func (o Options2003) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs          field.ErrorList
		acceptedPodsPath = fldPath.Child("acceptedPods")
	)
	for pIdx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(pIdx))...)
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
	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "PodList"))), nil
	}

	if len(pods) == 0 {
		return rule.Result(r, rule.PassedCheckResult("The cluster does not have any Pods.", rule.NewTarget())), nil
	}

	filteredPods := kubeutils.FilterPodsByOwnerRef(pods)

	allNamespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "NamespaceList"))), nil
	}

	replicaSets, err := kubeutils.GetReplicaSets(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "ReplicaSetList"))), nil
	}

	var checkResults []rule.CheckResult
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
			if volume.ConfigMap == nil &&
				volume.CSI == nil &&
				volume.DownwardAPI == nil &&
				volume.EmptyDir == nil &&
				volume.Ephemeral == nil &&
				volume.PersistentVolumeClaim == nil &&
				volume.Projected == nil &&
				volume.Secret == nil {
				uses = true
				if accepted, justification, err := r.accepted(pod.Labels, allNamespaces[pod.Namespace].Labels, volume.Name); err != nil {
					return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
				} else if accepted {
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

func (r *Rule2003) accepted(podLabels, namespaceLabels map[string]string, volumeName string) (bool, string, error) {
	if r.Options == nil {
		return false, "", nil
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if matches, err := acceptedPod.Matches(podLabels, namespaceLabels, volumeName); err != nil {
			return false, "", err
		} else if matches {
			return true, acceptedPod.Justification, nil
		}
	}

	return false, "", nil
}
