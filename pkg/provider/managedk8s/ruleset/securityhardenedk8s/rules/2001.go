// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var (
	_ rule.Rule     = &Rule2001{}
	_ rule.Severity = &Rule2001{}
	_ option.Option = &Options2001{}
)

type Rule2001 struct {
	Client  client.Client
	Options *Options2001
}

type Options2001 struct {
	AcceptedPods []AcceptedPods2001 `json:"acceptedPods" yaml:"acceptedPods"`
}

type AcceptedPods2001 struct {
	option.PodSelector
	Justification string `json:"justification" yaml:"justification"`
}

// Validate validates that option configurations are correctly defined
func (o Options2001) Validate() field.ErrorList {
	var allErrs field.ErrorList

	for _, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate()...)
	}

	return allErrs
}

func (r *Rule2001) ID() string {
	return "2001"
}

func (r *Rule2001) Name() string {
	return "Containers must be forbidden to escalate privileges."
}

func (r *Rule2001) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule2001) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults              []rule.CheckResult
		allowsPrivilegeEscalation = func(securityContext corev1.SecurityContext) bool {
			var addsCapSysAdmin = false

			if securityContext.Capabilities != nil {
				// CAP_SYS_ADMIN only works on CRI-O. ref: https://github.com/kubernetes/kubernetes/issues/119568
				// Valiadated with `ubuntu` container, to check enabled capabilities the `capsh --print` command can be used.
				addsCapSysAdmin = slices.ContainsFunc(securityContext.Capabilities.Add, func(cap corev1.Capability) bool {
					return strings.ToUpper(string(cap)) == "SYS_ADMIN" || strings.ToUpper(string(cap)) == "CAP_SYS_ADMIN"
				})
			}

			// AllowPrivilegeEscalation is defaulted to true. ref: https://github.com/kubernetes/kubernetes/issues/118822
			// Valiadated with `ubuntu` container, to check if AllowPrivilegeEscalation is
			// enabled the `cat /proc/self/status | grep NoNewPrivs` command can be used.
			return securityContext.AllowPrivilegeEscalation == nil || *securityContext.AllowPrivilegeEscalation ||
				(securityContext.Privileged != nil && *securityContext.Privileged) ||
				addsCapSysAdmin
		}
	)

	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList"))), nil
	}

	namespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "namespaceList"))), nil
	}

	for _, pod := range pods {
		podTarget := rule.NewTarget("kind", "pod", "name", pod.Name, "namespace", pod.Namespace)
		allows := false
		for _, container := range pod.Spec.Containers {
			var containerTarget = podTarget.With("container", container.Name)

			if container.SecurityContext == nil || allowsPrivilegeEscalation(*container.SecurityContext) {
				allows = true
				if accepted, justification := r.accepted(pod, namespaces[pod.Namespace]); accepted {
					msg := "Pod accepted to escalate privileges."
					if justification != "" {
						msg = justification
					}
					checkResults = append(checkResults, rule.AcceptedCheckResult(msg, containerTarget))
				} else {
					checkResults = append(checkResults, rule.FailedCheckResult("Pod must not escalate privileges.", containerTarget))
				}
			}
		}
		if !allows {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not escalate privileges.", podTarget))
		}
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule2001) accepted(pod corev1.Pod, namespace corev1.Namespace) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if utils.MatchLabels(pod.Labels, acceptedPod.PodMatchLabels) &&
			utils.MatchLabels(namespace.Labels, acceptedPod.NamespaceMatchLabels) {
			return true, acceptedPod.Justification
		}
	}

	return false, ""
}
