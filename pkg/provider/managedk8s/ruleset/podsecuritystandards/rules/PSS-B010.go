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

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule              = &RulePSSB010{}
	_ rule.Severity          = &RulePSSB010{}
	_ option.Option          = &OptionsPSSB010{}
	_ option.MergeableOption = &OptionsPSSB010{}
)

type RulePSSB010 struct {
	Client  client.Client
	Options *OptionsPSSB010
}

type OptionsPSSB010 struct {
	AcceptedPods []option.AcceptedNamespacedObject `json:"acceptedPods" yaml:"acceptedPods"`
}

// Validate validates that option configurations are correctly defined.
func (o OptionsPSSB010) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedPodsPath := fldPath.Child("acceptedPods")

	for pIdx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(pIdx))...)
	}

	return allErrs
}

// Merge returns a new OptionsPSSB010 that is the result of merging other into the receiver.
// AcceptedPods slices are concatenated. If other is not *OptionsPSSB010, an error is returned.
func (o *OptionsPSSB010) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if option.IsNilValue(other) {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*OptionsPSSB010](other)
	if err != nil {
		return nil, err
	}

	merged := &OptionsPSSB010{
		AcceptedPods: make([]option.AcceptedNamespacedObject, 0, len(o.AcceptedPods)+len(otherOpts.AcceptedPods)),
	}
	merged.AcceptedPods = append(merged.AcceptedPods, o.AcceptedPods...)
	merged.AcceptedPods = append(merged.AcceptedPods, otherOpts.AcceptedPods...)

	return merged, nil
}

func (r *RulePSSB010) ID() string {
	return "PSS-B010"
}

func (r *RulePSSB010) Name() string {
	return "/proc Mount Type"
}

func (r *RulePSSB010) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *RulePSSB010) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults   []rule.CheckResult
		validProcMount = func(procMount *corev1.ProcMountType) bool {
			return procMount == nil || *procMount == corev1.DefaultProcMount
		}
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
		var (
			podCheckResults []rule.CheckResult
			podTarget       = kubeutils.TargetWithPod(rule.NewTarget(), pod, replicaSets)

			checkProcMount = func(procMount *corev1.ProcMountType, target rule.Target) error {
				if validProcMount(procMount) {
					return nil
				}

				if accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels); err != nil {
					return err
				} else if accepted {
					msg := cmp.Or(justification, "Pod accepted to use a non-default /proc mount type.")
					podCheckResults = append(podCheckResults, rule.AcceptedCheckResult(msg, target))
				} else {
					podCheckResults = append(podCheckResults, rule.FailedCheckResult("Pod must not use a non-default /proc mount type.", target))
				}
				return nil
			}
		)

		for _, container := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			containerTarget := podTarget.With("container", container.Name)
			var procMount *corev1.ProcMountType

			if container.SecurityContext != nil {
				procMount = container.SecurityContext.ProcMount
			}
			if err := checkProcMount(procMount, containerTarget); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		for _, ephemeralContainer := range pod.Spec.EphemeralContainers {
			containerTarget := podTarget.With("container", ephemeralContainer.Name)
			var procMount *corev1.ProcMountType

			if ephemeralContainer.SecurityContext != nil {
				procMount = ephemeralContainer.SecurityContext.ProcMount
			}
			if err := checkProcMount(procMount, containerTarget); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod uses the default /proc mount type.", podTarget))
		}
		checkResults = append(checkResults, podCheckResults...)
	}

	return rule.Result(r, checkResults...), nil
}

func (r *RulePSSB010) accepted(podLabels, namespaceLabels map[string]string) (bool, string, error) {
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
