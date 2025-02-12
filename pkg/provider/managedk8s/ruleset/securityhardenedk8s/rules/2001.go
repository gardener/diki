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
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
	disaoptions "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var (
	_ rule.Rule          = &Rule2001{}
	_ rule.Severity      = &Rule2001{}
	_ disaoptions.Option = &Options2001{}
)

type Rule2001 struct {
	Client  client.Client
	Options *Options2001
}

type Options2001 struct {
	AcceptedPods []option.AcceptedNamespacedObject `json:"acceptedPods" yaml:"acceptedPods"`
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
		checkResults []rule.CheckResult
	)

	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList"))), nil
	}

	if len(pods) == 0 {
		return rule.Result(r, rule.PassedCheckResult("The cluster does not have any Pods.", rule.NewTarget())), nil
	}

	namespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "namespaceList"))), nil
	}

	for _, pod := range pods {
		var (
			podCheckResults []rule.CheckResult
			podTarget       = rule.NewTarget("kind", "pod", "name", pod.Name, "namespace", pod.Namespace)
		)
		for _, container := range pod.Spec.Containers {
			podCheckResults = append(podCheckResults, r.checkContainer(container, pod.Labels, namespaces[pod.Namespace].Labels, podTarget)...)
		}
		for _, container := range pod.Spec.InitContainers {
			podCheckResults = append(podCheckResults, r.checkContainer(container, pod.Labels, namespaces[pod.Namespace].Labels, podTarget)...)
		}
		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not escalate privileges.", podTarget))
		}
		checkResults = append(checkResults, podCheckResults...)
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule2001) checkContainer(container corev1.Container, podLabels, namespaceLabels map[string]string, target rule.Target) []rule.CheckResult {
	var (
		checkResults              []rule.CheckResult
		containerTarget           = target.With("container", container.Name)
		allowsPrivilegeEscalation = func(securityContext corev1.SecurityContext) bool {
			addsCapSysAdmin := false

			if securityContext.Capabilities != nil {
				// CAP_SYS_ADMIN only works on CRI-O. ref: https://github.com/kubernetes/kubernetes/issues/119568
				// Valiadated with `ubuntu` container, to check enabled capabilities the `capsh --print` command can be used.
				addsCapSysAdmin = slices.ContainsFunc(securityContext.Capabilities.Add, func(capability corev1.Capability) bool {
					return strings.ToUpper(string(capability)) == "SYS_ADMIN" || strings.ToUpper(string(capability)) == "CAP_SYS_ADMIN"
				})
			}

			// AllowPrivilegeEscalation is defaulted to true. ref: https://github.com/kubernetes/kubernetes/issues/118822
			// Valiadated with `ubuntu` container, to check if AllowPrivilegeEscalation is
			// enabled the `cat /proc/self/status | grep NoNewPrivs` command can be used.
			var (
				allowsPrivilegeEscalation = securityContext.AllowPrivilegeEscalation == nil || *securityContext.AllowPrivilegeEscalation
				hasPrivilegedContext      = securityContext.Privileged != nil && *securityContext.Privileged
			)
			return allowsPrivilegeEscalation || hasPrivilegedContext || addsCapSysAdmin
		}
	)

	if container.SecurityContext == nil || allowsPrivilegeEscalation(*container.SecurityContext) {
		if accepted, justification := r.accepted(podLabels, namespaceLabels); accepted {
			msg := "Pod accepted to escalate privileges."
			if justification != "" {
				msg = justification
			}
			checkResults = append(checkResults, rule.AcceptedCheckResult(msg, containerTarget))
		} else {
			checkResults = append(checkResults, rule.FailedCheckResult("Pod must not escalate privileges.", containerTarget))
		}
	}

	return checkResults
}

func (r *Rule2001) accepted(podLabels, namespaceLabels map[string]string) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if utils.MatchLabels(podLabels, acceptedPod.MatchLabels) &&
			utils.MatchLabels(namespaceLabels, acceptedPod.NamespaceMatchLabels) {
			return true, acceptedPod.Justification
		}
	}

	return false, ""
}
