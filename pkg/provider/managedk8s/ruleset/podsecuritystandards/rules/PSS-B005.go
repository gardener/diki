// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
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
	_ rule.Rule              = &RulePSSB005{}
	_ rule.Severity          = &RulePSSB005{}
	_ option.Option          = &OptionsPSSB005{}
	_ option.MergeableOption = &OptionsPSSB005{}
)

type RulePSSB005 struct {
	Client  client.Client
	Options *OptionsPSSB005
}

func (r *RulePSSB005) ID() string {
	return "PSS-B005"
}

func (r *RulePSSB005) Name() string {
	return "Host Path volumes must be forbidden."
}

func (r *RulePSSB005) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

type OptionsPSSB005 struct {
	AcceptedPods []option.AcceptedPodVolumes `json:"acceptedPods" yaml:"acceptedPods"`
}

// Validate validates that option configurations are correctly defined.
func (o *OptionsPSSB005) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedPodsPath := fldPath.Child("acceptedPods")

	for pIdx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(pIdx))...)
	}

	return allErrs
}

// Merge returns a new OptionsPSSB005 that is the result of merging other into the receiver.
// AcceptedPods slices are concatenated. If other is not *OptionsPSSB005, an error is returned.
func (o *OptionsPSSB005) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if option.IsNilValue(other) {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*OptionsPSSB005](other)
	if err != nil {
		return nil, err
	}

	merged := &OptionsPSSB005{
		AcceptedPods: make([]option.AcceptedPodVolumes, 0, len(o.AcceptedPods)+len(otherOpts.AcceptedPods)),
	}
	merged.AcceptedPods = append(merged.AcceptedPods, o.AcceptedPods...)
	merged.AcceptedPods = append(merged.AcceptedPods, otherOpts.AcceptedPods...)

	return merged, nil
}

// Run implements [rule.Rule].
func (r *RulePSSB005) Run(ctx context.Context) (rule.RuleResult, error) {
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
			uses      = false
			podTarget = kubeutils.TargetWithPod(rule.NewTarget(), pod, replicaSets)
		)

		// Diki privileged pod uses hostPath volume. During execution, parallel diki rules might create pods.
		if utils.MatchLabels(pod.Labels, map[string]string{
			kubepod.LabelComplianceRoleKey: kubepod.LabelComplianceRolePrivPod,
		}) {
			checkResults = append(checkResults, rule.SkippedCheckResult("Diki privileged pod requires the use of hostPaths.", podTarget))
			continue
		}

		for _, volume := range pod.Spec.Volumes {
			if volume.HostPath == nil {
				continue
			}
			uses = true
			volumeTarget := podTarget.With("volume", volume.Name)
			if accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels, volume.Name); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			} else if accepted {
				msg := cmp.Or(justification, "Pod accepted to use volume of type hostPath.")
				checkResults = append(checkResults, rule.AcceptedCheckResult(msg, volumeTarget))
			} else {
				checkResults = append(checkResults, rule.FailedCheckResult("Pod must not use volumes of type hostPath.", volumeTarget))
			}
		}

		if !uses {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not use volumes of type hostPath.", podTarget))
		}
	}

	return rule.Result(r, checkResults...), nil
}

func (r *RulePSSB005) accepted(podLabels, namespaceLabels map[string]string, volumeName string) (bool, string, error) {
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
