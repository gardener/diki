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
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule              = &RulePSSB004{}
	_ rule.Severity          = &RulePSSB004{}
	_ option.Option          = &OptionsPSSB004{}
	_ option.MergeableOption = &OptionsPSSB004{}
)

// baselineAllowedCapabilities is the set of capabilities allowed to be added
// by the Pod Security Standards baseline profile, normalized to upper case
// without the optional "CAP_" prefix.
// ref: https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
var baselineAllowedCapabilities = sets.New(
	"AUDIT_WRITE",
	"CHOWN",
	"DAC_OVERRIDE",
	"FOWNER",
	"FSETID",
	"KILL",
	"MKNOD",
	"NET_BIND_SERVICE",
	"SETFCAP",
	"SETGID",
	"SETPCAP",
	"SETUID",
	"SYS_CHROOT",
)

type RulePSSB004 struct {
	Client  client.Client
	Options *OptionsPSSB004
}

func (r *RulePSSB004) ID() string {
	return "PSS-B004"
}

func (r *RulePSSB004) Name() string {
	return "Containers must not add capabilities beyond those allowed by the Pod Security Standards baseline profile."
}

func (r *RulePSSB004) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

type OptionsPSSB004 struct {
	AcceptedPods []option.AcceptedNamespacedObject `json:"acceptedPods" yaml:"acceptedPods"`
}

// Validate validates that option configurations are correctly defined.
func (o *OptionsPSSB004) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedPodsPath := fldPath.Child("acceptedPods")

	for pIdx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(pIdx))...)
	}

	return allErrs
}

// Merge returns a new OptionsPSSB004 that is the result of merging other into the receiver.
// AcceptedPods slices are concatenated. If other is not *OptionsPSSB004, an error is returned.
func (o *OptionsPSSB004) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if option.IsNilValue(other) {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*OptionsPSSB004](other)
	if err != nil {
		return nil, err
	}

	merged := &OptionsPSSB004{
		AcceptedPods: make([]option.AcceptedNamespacedObject, 0, len(o.AcceptedPods)+len(otherOpts.AcceptedPods)),
	}
	merged.AcceptedPods = append(merged.AcceptedPods, o.AcceptedPods...)
	merged.AcceptedPods = append(merged.AcceptedPods, otherOpts.AcceptedPods...)

	return merged, nil
}

// Run implements [rule.Rule].
func (r *RulePSSB004) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults []rule.CheckResult

		disallowedCapability = func(sc *corev1.SecurityContext) (corev1.Capability, bool) {
			if sc == nil || sc.Capabilities == nil {
				return "", false
			}
			for _, c := range sc.Capabilities.Add {
				normalized := strings.TrimPrefix(strings.ToUpper(string(c)), "CAP_")
				if !baselineAllowedCapabilities.Has(normalized) {
					return c, true
				}
			}
			return "", false
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

			checkContainerCapabilities = func(name string, sc *corev1.SecurityContext) error {
				capability, found := disallowedCapability(sc)
				if !found {
					return nil
				}

				containerTarget := podTarget.With("container", name, "capability", string(capability))
				if accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels); err != nil {
					return err
				} else if accepted {
					msg := cmp.Or(justification, "Pod accepted to add disallowed capabilities.")
					podCheckResults = append(podCheckResults, rule.AcceptedCheckResult(msg, containerTarget))
				} else {
					podCheckResults = append(podCheckResults, rule.FailedCheckResult("Pod must not add capabilities beyond the allowed baseline list.", containerTarget))
				}
				return nil
			}
		)

		for _, c := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			if err := checkContainerCapabilities(c.Name, c.SecurityContext); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}
		for _, c := range pod.Spec.EphemeralContainers {
			if err := checkContainerCapabilities(c.Name, c.SecurityContext); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not add disallowed capabilities.", podTarget))
		}
		checkResults = append(checkResults, podCheckResults...)
	}

	return rule.Result(r, checkResults...), nil
}

func (r *RulePSSB004) accepted(podLabels, namespaceLabels map[string]string) (bool, string, error) {
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
