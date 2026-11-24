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
	_ rule.Rule              = &RulePSSB009{}
	_ rule.Severity          = &RulePSSB009{}
	_ option.Option          = &OptionsPSSB009{}
	_ option.MergeableOption = &OptionsPSSB009{}
)

type RulePSSB009 struct {
	Client  client.Client
	Options *OptionsPSSB009
}

type OptionsPSSB009 struct {
	AcceptedPods []option.AcceptedNamespacedObject `json:"acceptedPods" yaml:"acceptedPods"`
}

// Validate validates that option configurations are correctly defined.
func (o OptionsPSSB009) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedPodsPath := fldPath.Child("acceptedPods")

	for pIdx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(pIdx))...)
	}

	return allErrs
}

// Merge returns a new OptionsPSSB009 that is the result of merging other into the receiver.
// AcceptedPods slices are concatenated. If other is not *OptionsPSSB009, an error is returned.
func (o *OptionsPSSB009) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if option.IsNilValue(other) {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*OptionsPSSB009](other)
	if err != nil {
		return nil, err
	}

	merged := &OptionsPSSB009{
		AcceptedPods: make([]option.AcceptedNamespacedObject, 0, len(o.AcceptedPods)+len(otherOpts.AcceptedPods)),
	}
	merged.AcceptedPods = append(merged.AcceptedPods, o.AcceptedPods...)
	merged.AcceptedPods = append(merged.AcceptedPods, otherOpts.AcceptedPods...)

	return merged, nil
}

func (r *RulePSSB009) ID() string {
	return "PSS-B009"
}

func (r *RulePSSB009) Name() string {
	return "SELinux"
}

func (r *RulePSSB009) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *RulePSSB009) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults        []rule.CheckResult
		allowedTypes        = []string{"container_t", "container_init_t", "container_kvm_t", "container_engine_t"}
		validSELinuxOptions = func(seLinuxOptions *corev1.SELinuxOptions) bool {
			return seLinuxOptions == nil ||
				(seLinuxOptions.User == "" &&
					seLinuxOptions.Role == "" &&
					(seLinuxOptions.Type == "" || slices.Contains(allowedTypes, seLinuxOptions.Type)))
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

			checkSELinuxOptions = func(seLinuxOptions *corev1.SELinuxOptions, target rule.Target) error {
				if validSELinuxOptions(seLinuxOptions) {
					return nil
				}

				if accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels); err != nil {
					return err
				} else if accepted {
					msg := cmp.Or(justification, "Pod accepted to set forbidden SELinux options.")
					podCheckResults = append(podCheckResults, rule.AcceptedCheckResult(msg, target))
				} else {
					podCheckResults = append(podCheckResults, rule.FailedCheckResult("Pod must not set forbidden SELinux options.", target))
				}
				return nil
			}
		)

		if pod.Spec.SecurityContext != nil {
			if err := checkSELinuxOptions(pod.Spec.SecurityContext.SELinuxOptions, podTarget); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		for _, container := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			containerTarget := podTarget.With("container", container.Name)
			var seLinuxOptions *corev1.SELinuxOptions

			if container.SecurityContext != nil {
				seLinuxOptions = container.SecurityContext.SELinuxOptions
			}
			if err := checkSELinuxOptions(seLinuxOptions, containerTarget); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		for _, ephemeralContainer := range pod.Spec.EphemeralContainers {
			containerTarget := podTarget.With("container", ephemeralContainer.Name)
			var seLinuxOptions *corev1.SELinuxOptions

			if ephemeralContainer.SecurityContext != nil {
				seLinuxOptions = ephemeralContainer.SecurityContext.SELinuxOptions
			}
			if err := checkSELinuxOptions(seLinuxOptions, containerTarget); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod uses allowed SELinux options.", podTarget))
		}
		checkResults = append(checkResults, podCheckResults...)
	}

	return rule.Result(r, checkResults...), nil
}

func (r *RulePSSB009) accepted(podLabels, namespaceLabels map[string]string) (bool, string, error) {
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
