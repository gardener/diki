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
	_ rule.Rule     = &Rule242414{}
	_ rule.Severity = &Rule242414{}
)

type Rule242414 struct {
	Client  client.Client
	Options *option.Options242414
}

func (r *Rule242414) ID() string {
	return sharedrules.ID242414
}

func (r *Rule242414) Name() string {
	return "The Kubernetes cluster must use non-privileged host ports for user pods."
}

func (r *Rule242414) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242414) Run(ctx context.Context) (rule.RuleResult, error) {
	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "PodList"))), nil
	}
	filteredPods := kubeutils.FilterPodsByOwnerRef(pods)

	replicaSets, err := kubeutils.GetReplicaSets(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "ReplicaSetList"))), nil
	}

	namespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "NamespaceList"))), nil
	}
	checkResults, err := r.checkPods(filteredPods, replicaSets, namespaces)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), err
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule242414) checkPods(pods []corev1.Pod, replicaSets []appsv1.ReplicaSet, namespaces map[string]corev1.Namespace) ([]rule.CheckResult, error) {
	var checkResults []rule.CheckResult
	for _, pod := range pods {
		var (
			podCheckResults []rule.CheckResult
			target          = kubeutils.TargetWithPod(rule.NewTarget(), pod, replicaSets)
		)
		for _, container := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			for _, port := range container.Ports {
				if port.HostPort != 0 && port.HostPort < 1024 {
					target := target.With("container", container.Name, "details", fmt.Sprintf("port: %d", port.HostPort))
					if accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels, port.HostPort); err != nil {
						return nil, err
					} else if accepted {
						msg := cmp.Or(justification, "Pod accepted to have containers using hostPort < 1024.")
						podCheckResults = append(podCheckResults, rule.AcceptedCheckResult(msg, target))
					} else {
						podCheckResults = append(podCheckResults, rule.FailedCheckResult("Pod has container using hostPort < 1024.", target))
					}
				}
			}
		}
		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not have container using hostPort < 1024.", target))
		}
		checkResults = append(checkResults, podCheckResults...)
	}
	return checkResults, nil
}

func (r *Rule242414) accepted(podLabels, namespaceLabels map[string]string, hostPort int32) (bool, string, error) {
	if r.Options == nil {
		return false, "", nil
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if matches, err := acceptedPod.Matches(podLabels, namespaceLabels); err != nil {
			return false, "", err
		} else if matches {
			for _, acceptedHostPort := range acceptedPod.Ports {
				if acceptedHostPort == hostPort {
					return true, acceptedPod.Justification, nil
				}
			}
		}
	}

	return false, "", nil
}
