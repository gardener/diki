// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"context"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule              = &RulePSSB008{}
	_ rule.Severity          = &RulePSSB008{}
	_ option.Option          = &OptionsPSSB008{}
	_ option.MergeableOption = &OptionsPSSB008{}
)

type RulePSSB008 struct {
	Client  client.Client
	Options *OptionsPSSB008
}

type OptionsPSSB008 struct {
	AcceptedPods []option.AcceptedNamespacedObject `json:"acceptedPods" yaml:"acceptedPods"`
}

// Validate validates that option configurations are correctly defined.
func (o OptionsPSSB008) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedPodsPath := fldPath.Child("acceptedPods")

	for pIdx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(pIdx))...)
	}

	return allErrs
}

// Merge returns a new OptionsPSSB008 that is the result of merging other into the receiver.
// AcceptedPods slices are concatenated. If other is not *OptionsPSSB008, an error is returned.
func (o *OptionsPSSB008) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if option.IsNilValue(other) {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*OptionsPSSB008](other)
	if err != nil {
		return nil, err
	}

	merged := &OptionsPSSB008{
		AcceptedPods: make([]option.AcceptedNamespacedObject, 0, len(o.AcceptedPods)+len(otherOpts.AcceptedPods)),
	}
	merged.AcceptedPods = append(merged.AcceptedPods, o.AcceptedPods...)
	merged.AcceptedPods = append(merged.AcceptedPods, otherOpts.AcceptedPods...)

	return merged, nil
}

func (r *RulePSSB008) ID() string {
	return "PSS-B008"
}

func (r *RulePSSB008) Name() string {
	return "AppArmor"
}

func (r *RulePSSB008) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *RulePSSB008) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults      []rule.CheckResult
		validAppArmorType = func(appArmorProfile *corev1.AppArmorProfile) bool {
			return appArmorProfile == nil || appArmorProfile.Type == corev1.AppArmorProfileTypeRuntimeDefault || appArmorProfile.Type == corev1.AppArmorProfileTypeLocalhost
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

			checkAppArmorProfile = func(appArmorProfile *corev1.AppArmorProfile, containerName string, target rule.Target) error {
				if appArmorProfile == nil && containerName != "" {
					annotationValue, ok := pod.Annotations["container.apparmor.security.beta.kubernetes.io/"+containerName]
					if !ok || annotationValue == "runtime/default" || strings.HasPrefix(annotationValue, "localhost/") {
						return nil
					}
				} else if validAppArmorType(appArmorProfile) {
					return nil
				}

				if accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels); err != nil {
					return err
				} else if accepted {
					msg := cmp.Or(justification, "Pod accepted to use unallowed AppArmor profile.")
					podCheckResults = append(podCheckResults, rule.AcceptedCheckResult(msg, target))
				} else {
					podCheckResults = append(podCheckResults, rule.FailedCheckResult("Pod must use an allowed AppArmor profile.", target))
				}
				return nil
			}
		)

		if pod.Spec.SecurityContext != nil {
			if err := checkAppArmorProfile(pod.Spec.SecurityContext.AppArmorProfile, "", podTarget); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		for _, container := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			containerTarget := podTarget.With("container", container.Name)
			var appArmorProfile *corev1.AppArmorProfile
			if container.SecurityContext != nil {
				appArmorProfile = container.SecurityContext.AppArmorProfile
			}
			if err := checkAppArmorProfile(appArmorProfile, container.Name, containerTarget); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		for _, ephemeralContainer := range pod.Spec.EphemeralContainers {
			containerTarget := podTarget.With("container", ephemeralContainer.Name)
			var appArmorProfile *corev1.AppArmorProfile
			if ephemeralContainer.SecurityContext != nil {
				appArmorProfile = ephemeralContainer.SecurityContext.AppArmorProfile
			}
			if err := checkAppArmorProfile(appArmorProfile, ephemeralContainer.Name, containerTarget); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod uses an allowed AppArmor profile.", podTarget))
		}
		checkResults = append(checkResults, podCheckResults...)
	}

	return rule.Result(r, checkResults...), nil
}

func (r *RulePSSB008) accepted(podLabels, namespaceLabels map[string]string) (bool, string, error) {
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
