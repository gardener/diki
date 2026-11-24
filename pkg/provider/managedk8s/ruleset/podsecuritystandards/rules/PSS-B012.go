// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"context"
	"slices"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule              = &RulePSSB012{}
	_ rule.Severity          = &RulePSSB012{}
	_ option.Option          = &OptionsPSSB012{}
	_ option.MergeableOption = &OptionsPSSB012{}
)

type RulePSSB012 struct {
	Client  client.Client
	Options *OptionsPSSB012
}

type OptionsPSSB012 struct {
	AcceptedPods []option.AcceptedNamespacedObject `json:"acceptedPods" yaml:"acceptedPods"`
}

// Validate validates that option configurations are correctly defined.
func (o OptionsPSSB012) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedPodsPath := fldPath.Child("acceptedPods")

	for pIdx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(pIdx))...)
	}

	return allErrs
}

// Merge returns a new OptionsPSSB012 that is the result of merging other into the receiver.
// AcceptedPods slices are concatenated. If other is not *OptionsPSSB012, an error is returned.
func (o *OptionsPSSB012) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if option.IsNilValue(other) {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*OptionsPSSB012](other)
	if err != nil {
		return nil, err
	}

	merged := &OptionsPSSB012{
		AcceptedPods: make([]option.AcceptedNamespacedObject, 0, len(o.AcceptedPods)+len(otherOpts.AcceptedPods)),
	}
	merged.AcceptedPods = append(merged.AcceptedPods, o.AcceptedPods...)
	merged.AcceptedPods = append(merged.AcceptedPods, otherOpts.AcceptedPods...)

	return merged, nil
}

func (r *RulePSSB012) ID() string {
	return "PSS-B012"
}

func (r *RulePSSB012) Name() string {
	return "Sysctls"
}

func (r *RulePSSB012) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *RulePSSB012) Run(ctx context.Context) (rule.RuleResult, error) {
	var checkResults []rule.CheckResult

	allowedSysctls := []string{
		"kernel.shm_rmid_forced",
		"net.ipv4.ip_local_port_range",
		"net.ipv4.ip_local_reserved_ports",
		"net.ipv4.ip_unprivileged_port_start",
		"net.ipv4.ping_group_range",
		"net.ipv4.tcp_fin_timeout",
		"net.ipv4.tcp_keepalive_intvl",
		"net.ipv4.tcp_keepalive_probes",
		"net.ipv4.tcp_keepalive_time",
		"net.ipv4.tcp_notsent_lowat",
		"net.ipv4.tcp_rmem",
		"net.ipv4.tcp_slow_start_after_idle",
		"net.ipv4.tcp_syncookies",
		"net.ipv4.tcp_wmem",
	}

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

		if pod.Spec.SecurityContext != nil {
			for _, sysctl := range pod.Spec.SecurityContext.Sysctls {
				if slices.Contains(allowedSysctls, sysctl.Name) {
					continue
				}

				if accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels); err != nil {
					return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
				} else if accepted {
					msg := cmp.Or(justification, "Pod accepted to use unsafe sysctl.")
					podCheckResults = append(podCheckResults, rule.AcceptedCheckResult(msg, podTarget))
				} else {
					podCheckResults = append(podCheckResults, rule.FailedCheckResult("Pod must not use unsafe sysctl.", podTarget))
				}
			}
		}

		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not use unsafe sysctls.", podTarget))
		}
		checkResults = append(checkResults, podCheckResults...)
	}

	return rule.Result(r, checkResults...), nil
}

func (r *RulePSSB012) accepted(podLabels, namespaceLabels map[string]string) (bool, string, error) {
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
