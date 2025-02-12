// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var (
	_ rule.Rule     = &Rule242415{}
	_ rule.Severity = &Rule242415{}
)

type Rule242415 struct {
	Client  client.Client
	Options *option.Options242415
}

func (r *Rule242415) ID() string {
	return sharedrules.ID242415
}

func (r *Rule242415) Name() string {
	return "Secrets in Kubernetes must not be stored as environment variables."
}

func (r *Rule242415) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule242415) Run(ctx context.Context) (rule.RuleResult, error) {
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
	checkResults := r.checkPods(pods, namespaces)

	return rule.Result(r, checkResults...), nil
}

func (r *Rule242415) checkPods(pods []corev1.Pod, namespaces map[string]corev1.Namespace) []rule.CheckResult {
	var checkResults []rule.CheckResult
	for _, pod := range pods {
		var (
			podCheckResults []rule.CheckResult
			target          = rule.NewTarget("name", pod.Name, "namespace", pod.Namespace, "kind", "pod")
		)
		for _, container := range pod.Spec.Containers {
			podCheckResults = append(podCheckResults, r.checkContainer(container, pod.Labels, namespaces[pod.Namespace].Labels, target)...)
		}
		for _, container := range pod.Spec.InitContainers {
			podCheckResults = append(podCheckResults, r.checkContainer(container, pod.Labels, namespaces[pod.Namespace].Labels, target)...)
		}
		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not use environment to inject secret.", target))
		}
		checkResults = append(checkResults, podCheckResults...)
	}
	return checkResults
}

func (r *Rule242415) checkContainer(container corev1.Container, podLabels, namespaceLabels map[string]string, target rule.Target) []rule.CheckResult {
	var checkResults []rule.CheckResult

	for _, env := range container.Env {
		if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
			target = target.With("container", container.Name, "details", fmt.Sprintf("variableName: %s, keyRef: %s", env.Name, env.ValueFrom.SecretKeyRef.Key))
			if accepted, justification := r.accepted(podLabels, namespaceLabels, env.Name); accepted {
				msg := "Pod accepted to use environment to inject secret."
				if justification != "" {
					msg = justification
				}
				checkResults = append(checkResults, rule.AcceptedCheckResult(msg, target))
			} else {
				checkResults = append(checkResults, rule.FailedCheckResult("Pod uses environment to inject secret.", target))
			}
		}
	}

	return checkResults
}

func (r *Rule242415) accepted(podLabels, namespaceLabels map[string]string, environmentVariable string) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if utils.MatchLabels(podLabels, acceptedPod.PodMatchLabels) &&
			utils.MatchLabels(namespaceLabels, acceptedPod.NamespaceMatchLabels) {
			for _, acceptedEnvironmentVariable := range acceptedPod.EnvironmentVariables {
				if acceptedEnvironmentVariable == environmentVariable {
					return true, acceptedPod.Justification
				}
			}
		}
	}

	return false, ""
}
