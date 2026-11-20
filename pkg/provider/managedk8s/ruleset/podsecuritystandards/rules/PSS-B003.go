// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"context"
	"slices"

	corev1 "k8s.io/api/core/v1"
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
	_ rule.Rule              = &RulePSSB003{}
	_ rule.Severity          = &RulePSSB003{}
	_ option.Option          = &OptionsPSSB003{}
	_ option.MergeableOption = &OptionsPSSB003{}
)

type RulePSSB003 struct {
	Client  client.Client
	Options *OptionsPSSB003
}

func (r *RulePSSB003) ID() string {
	return "PSS-B003"
}

func (r *RulePSSB003) Name() string {
	return "Privileged Pods disable most security mechanisms and must be disallowed."
}

func (r *RulePSSB003) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

type OptionsPSSB003 struct {
	AcceptedPods []option.AcceptedNamespacedObject `json:"acceptedPods" yaml:"acceptedPods"`
}

// Validate validates that option configurations are correctly defined.
func (o *OptionsPSSB003) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedPodsPath := fldPath.Child("acceptedPods")

	for pIdx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(pIdx))...)
	}

	return allErrs
}

// Merge returns a new OptionsPSSB003 that is the result of merging other into the receiver.
// AcceptedPods slices are concatenated. If other is not *OptionsPSSB003, an error is returned.
func (o *OptionsPSSB003) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if option.IsNilValue(other) {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*OptionsPSSB003](other)
	if err != nil {
		return nil, err
	}

	merged := &OptionsPSSB003{
		AcceptedPods: make([]option.AcceptedNamespacedObject, 0, len(o.AcceptedPods)+len(otherOpts.AcceptedPods)),
	}
	merged.AcceptedPods = append(merged.AcceptedPods, o.AcceptedPods...)
	merged.AcceptedPods = append(merged.AcceptedPods, otherOpts.AcceptedPods...)

	return merged, nil
}

// Run implements [rule.Rule].
func (r *RulePSSB003) Run(ctx context.Context) (rule.RuleResult, error) {
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
			podCheckResults []rule.CheckResult
			podTarget       = kubeutils.TargetWithPod(rule.NewTarget(), pod, replicaSets)
		)

		if utils.MatchLabels(pod.Labels, map[string]string{
			kubepod.LabelComplianceRoleKey: kubepod.LabelComplianceRolePrivPod,
		}) {
			checkResults = append(checkResults, rule.SkippedCheckResult("Diki privileged pod requires privileged mode.", podTarget))
			continue
		}

		accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels)
		if err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
		}
		if accepted {
			msg := cmp.Or(justification, "Pod accepted to have privileged containers.")
			checkResults = append(checkResults, rule.AcceptedCheckResult(msg, podTarget))
			continue
		}

		checkPrivileged := func(name string, sc *corev1.SecurityContext) {
			if sc != nil && sc.Privileged != nil && *sc.Privileged {
				podCheckResults = append(podCheckResults, rule.FailedCheckResult("Container must not run in privileged mode.", podTarget.With("container", name)))
			}
		}

		for _, c := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			checkPrivileged(c.Name, c.SecurityContext)
		}
		for _, c := range pod.Spec.EphemeralContainers {
			checkPrivileged(c.Name, c.SecurityContext)
		}

		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not have privileged containers.", podTarget))
		}
		checkResults = append(checkResults, podCheckResults...)
	}

	return rule.Result(r, checkResults...), nil
}

func (r *RulePSSB003) accepted(podLabels, namespaceLabels map[string]string) (bool, string, error) {
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
