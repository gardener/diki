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
	_ rule.Rule              = &RulePSSB001{}
	_ rule.Severity          = &RulePSSB001{}
	_ option.Option          = &OptionsPSSB001{}
	_ option.MergeableOption = &OptionsPSSB001{}
)

type RulePSSB001 struct {
	Client  client.Client
	Options *OptionsPSSB001
}

func (r *RulePSSB001) ID() string {
	return "PSS-B001"
}

func (r *RulePSSB001) Name() string {
	return "Windows Pods should not run Host Process containers, as it enables privileged access to the Windows host machine."
}

func (r *RulePSSB001) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

type OptionsPSSB001 struct {
	AcceptedPods []option.AcceptedNamespacedObject `json:"acceptedPods" yaml:"acceptedPods"`
}

// Validate validates that option configurations are correctly defined.
func (o OptionsPSSB001) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedPodsPath := fldPath.Child("acceptedPods")

	for pIdx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(pIdx))...)
	}

	return allErrs
}

// Merge returns a new OptionsPSSB001 that is the result of merging other into the receiver.
// AcceptedPods slices are concatenated. If other is not *OptionsPSSB001, an error is returned.
func (o *OptionsPSSB001) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if option.IsNilValue(other) {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*OptionsPSSB001](other)
	if err != nil {
		return nil, err
	}

	merged := &OptionsPSSB001{
		AcceptedPods: make([]option.AcceptedNamespacedObject, 0, len(o.AcceptedPods)+len(otherOpts.AcceptedPods)),
	}
	merged.AcceptedPods = append(merged.AcceptedPods, o.AcceptedPods...)
	merged.AcceptedPods = append(merged.AcceptedPods, otherOpts.AcceptedPods...)

	return merged, nil
}

// Run implements [rule.Rule].
func (r *RulePSSB001) Run(ctx context.Context) (rule.RuleResult, error) {
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
		var (
			podCheckResults []rule.CheckResult
			podTarget       = kubeutils.TargetWithPod(rule.NewTarget(), pod, replicaSets)

			checkHostProcess = func(target rule.Target, windowsOptions *corev1.WindowsSecurityContextOptions) error {
				if windowsOptions == nil || windowsOptions.HostProcess == nil || !*windowsOptions.HostProcess {
					return nil
				}
				accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels)
				if err != nil {
					return err
				}
				if accepted {
					msg := cmp.Or(justification, "Pod accepted to have Host Process ability.")
					podCheckResults = append(podCheckResults, rule.AcceptedCheckResult(msg, target))
				} else {
					podCheckResults = append(podCheckResults, rule.FailedCheckResult("Pod must not have Host Process ability.", target))
				}
				return nil
			}

			containerWindowsOptions = func(sc *corev1.SecurityContext) *corev1.WindowsSecurityContextOptions {
				if sc == nil {
					return nil
				}
				return sc.WindowsOptions
			}
		)

		var podWindowsOptions *corev1.WindowsSecurityContextOptions
		if pod.Spec.SecurityContext != nil {
			podWindowsOptions = pod.Spec.SecurityContext.WindowsOptions
		}
		if err := checkHostProcess(podTarget, podWindowsOptions); err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
		}
		for _, c := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			if err := checkHostProcess(podTarget.With("container", c.Name), containerWindowsOptions(c.SecurityContext)); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}
		for _, c := range pod.Spec.EphemeralContainers {
			if err := checkHostProcess(podTarget.With("container", c.Name), containerWindowsOptions(c.SecurityContext)); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not have Host Process ability.", podTarget))
		}
		checkResults = append(checkResults, podCheckResults...)
	}

	return rule.Result(r, checkResults...), nil
}

func (r *RulePSSB001) accepted(podLabels, namespaceLabels map[string]string) (bool, string, error) {
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
