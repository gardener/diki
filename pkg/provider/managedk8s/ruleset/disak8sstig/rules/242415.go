// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

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
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "PodList"))), nil
	}

	if len(pods) == 0 {
		return rule.Result(r, rule.PassedCheckResult("The cluster does not have any Pods.", rule.NewTarget())), nil
	}

	namespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "NamespaceList"))), nil
	}

	replicaSets, err := kubeutils.GetReplicaSets(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "ReplicaSetList"))), nil
	}

	filteredPods := kubeutils.FilterPodsByOwnerRef(pods)

	checkResults, err := r.checkPods(filteredPods, replicaSets, namespaces)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule242415) checkPods(pods []corev1.Pod, replicaSets []appsv1.ReplicaSet, namespaces map[string]corev1.Namespace) ([]rule.CheckResult, error) {
	var checkResults []rule.CheckResult
	for _, pod := range pods {
		var (
			podCheckResults []rule.CheckResult
			target          = kubeutils.TargetWithPod(rule.NewTarget(), pod, replicaSets)
		)
		for _, container := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			for _, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					target = target.With("container", container.Name, "details", fmt.Sprintf("variableName: %s, keyRef: %s", env.Name, env.ValueFrom.SecretKeyRef.Key))
					if accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels, env.Name); err != nil {
						return nil, err
					} else if accepted {
						msg := cmp.Or(justification, "Pod accepted to use environment to inject secret.")
						podCheckResults = append(podCheckResults, rule.AcceptedCheckResult(msg, target))
					} else {
						podCheckResults = append(podCheckResults, rule.FailedCheckResult("Pod uses environment to inject secret.", target))
					}
				}
			}
		}
		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not use environment to inject secret.", target))
		}
		checkResults = append(checkResults, podCheckResults...)
	}
	return checkResults, nil
}

func (r *Rule242415) accepted(podLabels, namespaceLabels map[string]string, environmentVariable string) (bool, string, error) {
	if r.Options == nil {
		return false, "", nil
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if matches, err := acceptedPod.Matches(podLabels, namespaceLabels); err != nil {
			return false, "", err
		} else if matches {
			for _, acceptedEnvironmentVariable := range acceptedPod.EnvironmentVariables {
				if acceptedEnvironmentVariable == environmentVariable {
					return true, acceptedPod.Justification, nil
				}
			}
		}
	}

	return false, "", nil
}
