// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"

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
	ClusterClient         client.Client
	ControlPlaneClient    client.Client
	ControlPlaneNamespace string
	Options               *option.Options242415
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
	seedTarget := rule.NewTarget("cluster", "seed")
	shootTarget := rule.NewTarget("cluster", "shoot")

	seedPods, err := kubeutils.GetPods(ctx, r.ControlPlaneClient, r.ControlPlaneNamespace, labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), seedTarget.With("namespace", r.ControlPlaneNamespace, "kind", "podList"))), nil
	}

	seedNamespaces, err := kubeutils.GetNamespaces(ctx, r.ControlPlaneClient)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), seedTarget.With("kind", "namespaceList"))), nil
	}
	checkResults := r.checkPods(seedPods, seedNamespaces, seedTarget)

	shootPods, err := kubeutils.GetPods(ctx, r.ClusterClient, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "podList"))), nil
	}

	shootNamespaces, err := kubeutils.GetNamespaces(ctx, r.ClusterClient)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "namespaceList"))), nil
	}
	checkResults = append(checkResults, r.checkPods(shootPods, shootNamespaces, shootTarget)...)

	return rule.Result(r, checkResults...), nil
}

func (r *Rule242415) checkPods(pods []corev1.Pod, namespaces map[string]corev1.Namespace, clusterTarget rule.Target) []rule.CheckResult {
	var checkResults []rule.CheckResult
	for _, pod := range pods {
		var (
			podCheckResults []rule.CheckResult
			target          = clusterTarget.With("name", pod.Name, "namespace", pod.Namespace, "kind", "pod")
		)
		for _, container := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			for _, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					containerTarget := target.With("container", container.Name, "details", fmt.Sprintf("variableName: %s, keyRef: %s", env.Name, env.ValueFrom.SecretKeyRef.Key))
					if accepted, justification := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels, env.Name); accepted {
						msg := "Pod accepted to use environment to inject secret."
						if justification != "" {
							msg = justification
						}
						podCheckResults = append(podCheckResults, rule.AcceptedCheckResult(msg, containerTarget))
					} else {
						podCheckResults = append(podCheckResults, rule.FailedCheckResult("Pod uses environment to inject secret.", containerTarget))
					}
				}
			}
		}
		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not use environment to inject secret.", target))
		}
		checkResults = append(checkResults, podCheckResults...)
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
