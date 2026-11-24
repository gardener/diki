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
	_ rule.Rule              = &RulePSSB011{}
	_ rule.Severity          = &RulePSSB011{}
	_ option.Option          = &OptionsPSSB011{}
	_ option.MergeableOption = &OptionsPSSB011{}
)

type RulePSSB011 struct {
	Client  client.Client
	Options *OptionsPSSB011
}

type OptionsPSSB011 struct {
	AcceptedPods []option.AcceptedNamespacedObject `json:"acceptedPods" yaml:"acceptedPods"`
}

// Validate validates that option configurations are correctly defined.
func (o OptionsPSSB011) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedPodsPath := fldPath.Child("acceptedPods")

	for pIdx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(pIdx))...)
	}

	return allErrs
}

// Merge returns a new OptionsPSSB011 that is the result of merging other into the receiver.
// AcceptedPods slices are concatenated. If other is not *OptionsPSSB011, an error is returned.
func (o *OptionsPSSB011) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if option.IsNilValue(other) {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*OptionsPSSB011](other)
	if err != nil {
		return nil, err
	}

	merged := &OptionsPSSB011{
		AcceptedPods: make([]option.AcceptedNamespacedObject, 0, len(o.AcceptedPods)+len(otherOpts.AcceptedPods)),
	}
	merged.AcceptedPods = append(merged.AcceptedPods, o.AcceptedPods...)
	merged.AcceptedPods = append(merged.AcceptedPods, otherOpts.AcceptedPods...)

	return merged, nil
}

func (r *RulePSSB011) ID() string {
	return "PSS-B011"
}

func (r *RulePSSB011) Name() string {
	return "Seccomp (Baseline)"
}

func (r *RulePSSB011) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *RulePSSB011) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults        []rule.CheckResult
		validSeccompProfile = func(seccompProfile *corev1.SeccompProfile) bool {
			return seccompProfile == nil || seccompProfile.Type != corev1.SeccompProfileTypeUnconfined
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

			checkSeccompProfile = func(seccompProfile *corev1.SeccompProfile, target rule.Target) error {
				if validSeccompProfile(seccompProfile) {
					return nil
				}

				if accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels); err != nil {
					return err
				} else if accepted {
					msg := cmp.Or(justification, "Pod accepted to use Unconfined seccomp profile.")
					podCheckResults = append(podCheckResults, rule.AcceptedCheckResult(msg, target))
				} else {
					podCheckResults = append(podCheckResults, rule.FailedCheckResult("Pod must not use Unconfined seccomp profile.", target))
				}
				return nil
			}
		)

		if pod.Spec.SecurityContext != nil {
			if err := checkSeccompProfile(pod.Spec.SecurityContext.SeccompProfile, podTarget); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		for _, container := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			containerTarget := podTarget.With("container", container.Name)
			var seccompProfile *corev1.SeccompProfile

			if container.SecurityContext != nil {
				seccompProfile = container.SecurityContext.SeccompProfile
			}
			if err := checkSeccompProfile(seccompProfile, containerTarget); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		for _, ephemeralContainer := range pod.Spec.EphemeralContainers {
			containerTarget := podTarget.With("container", ephemeralContainer.Name)
			var seccompProfile *corev1.SeccompProfile

			if ephemeralContainer.SecurityContext != nil {
				seccompProfile = ephemeralContainer.SecurityContext.SeccompProfile
			}
			if err := checkSeccompProfile(seccompProfile, containerTarget); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not use Unconfined seccomp profile.", podTarget))
		}
		checkResults = append(checkResults, podCheckResults...)
	}

	return rule.Result(r, checkResults...), nil
}

func (r *RulePSSB011) accepted(podLabels, namespaceLabels map[string]string) (bool, string, error) {
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
