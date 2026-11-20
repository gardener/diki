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

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule              = &RulePSSB002{}
	_ rule.Severity          = &RulePSSB002{}
	_ option.Option          = &OptionsPSSB002{}
	_ option.MergeableOption = &OptionsPSSB002{}
)

type RulePSSB002 struct {
	Client  client.Client
	Options *OptionsPSSB002
}

func (r *RulePSSB002) ID() string {
	return "PSS-B002"
}

func (r *RulePSSB002) Name() string {
	return "Sharing the host namespaces must be disallowed."
}

func (r *RulePSSB002) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

type OptionsPSSB002 struct {
	AcceptedPods []option.AcceptedNamespacedObject `json:"acceptedPods" yaml:"acceptedPods"`
}

// Validate validates that option configurations are correctly defined.
func (o *OptionsPSSB002) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedPodsPath := fldPath.Child("acceptedPods")

	for pIdx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(pIdx))...)
	}

	return allErrs
}

// Merge returns a new OptionsPSSB002 that is the result of merging other into the receiver.
// AcceptedPods slices are concatenated. If other is not *OptionsPSSB002, an error is returned.
func (o *OptionsPSSB002) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if option.IsNilValue(other) {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*OptionsPSSB002](other)
	if err != nil {
		return nil, err
	}

	merged := &OptionsPSSB002{
		AcceptedPods: make([]option.AcceptedNamespacedObject, 0, len(o.AcceptedPods)+len(otherOpts.AcceptedPods)),
	}
	merged.AcceptedPods = append(merged.AcceptedPods, o.AcceptedPods...)
	merged.AcceptedPods = append(merged.AcceptedPods, otherOpts.AcceptedPods...)

	return merged, nil
}

// Run implements [rule.Rule].
func (r *RulePSSB002) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults []rule.CheckResult
	)

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
		podTarget := kubeutils.TargetWithPod(rule.NewTarget(), pod, replicaSets)

		accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels)
		if err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
		}
		if accepted {
			msg := cmp.Or(justification, "Pod accepted to share host namespaces.")
			checkResults = append(checkResults, rule.AcceptedCheckResult(msg, podTarget))
			continue
		}

		if pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC {
			checkResults = append(checkResults, rule.FailedCheckResult("Pod must not share host namespaces.", podTarget))
			continue
		}

		checkResults = append(checkResults, rule.PassedCheckResult("Pod does not share host namespaces.", podTarget))
	}

	return rule.Result(r, checkResults...), nil
}

func (r *RulePSSB002) accepted(podLabels, namespaceLabels map[string]string) (bool, string, error) {
	if r.Options == nil {
		return false, "", nil
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if matches, err := acceptedPod.Matches(podLabels, namespaceLabels); err != nil {
			return false, "", err
		} else if matches {
			return true, acceptedPod.Justification, nil
		}
	}

	return false, "", nil
}
