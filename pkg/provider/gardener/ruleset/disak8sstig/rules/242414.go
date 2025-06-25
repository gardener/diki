// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
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

	"github.com/gardener/diki/pkg/internal/utils"
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
	ControlPlaneClient    client.Client
	ControlPlaneNamespace string
	ClusterClient         client.Client
	Options               *option.Options242414
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
	var (
		seedTarget  = rule.NewTarget("cluster", "seed")
		shootTarget = rule.NewTarget("cluster", "shoot")
	)

	seedPods, err := kubeutils.GetPods(ctx, r.ControlPlaneClient, r.ControlPlaneNamespace, labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), seedTarget.With("namespace", r.ControlPlaneNamespace, "kind", "PodList"))), nil
	}

	filteredSeedPods := kubeutils.FilterPodsByOwnerRef(seedPods)

	seedReplicaSets, err := kubeutils.GetReplicaSets(ctx, r.ControlPlaneClient, r.ControlPlaneNamespace, labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("namespace", r.ControlPlaneNamespace, "kind", "ReplicaSetList"))), nil
	}

	seedNamespaces, err := kubeutils.GetNamespaces(ctx, r.ControlPlaneClient)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), seedTarget.With("kind", "NamespaceList"))), nil
	}
	checkResults := r.checkPods(filteredSeedPods, seedReplicaSets, seedNamespaces, seedTarget)

	shootPods, err := kubeutils.GetPods(ctx, r.ClusterClient, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, append(checkResults, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "PodList")))...), nil
	}
	filteredShootPods := kubeutils.FilterPodsByOwnerRef(shootPods)

	shootReplicaSets, err := kubeutils.GetReplicaSets(ctx, r.ClusterClient, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "ReplicaSetList"))), nil
	}

	shootNamespaces, err := kubeutils.GetNamespaces(ctx, r.ClusterClient)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "NamespaceList"))), nil
	}
	checkResults = append(checkResults, r.checkPods(filteredShootPods, shootReplicaSets, shootNamespaces, shootTarget)...)

	return rule.Result(r, checkResults...), nil
}

func (r *Rule242414) checkPods(pods []corev1.Pod, replicaSets []appsv1.ReplicaSet, namespaces map[string]corev1.Namespace, clusterTarget rule.Target) []rule.CheckResult {
	var checkResults []rule.CheckResult
	for _, pod := range pods {
		var (
			podCheckResults []rule.CheckResult
			target          = kubeutils.TargetWithPod(clusterTarget, pod, replicaSets)
		)
		for _, container := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			for _, port := range container.Ports {
				if port.HostPort != 0 && port.HostPort < 1024 {
					containertTarget := target.With("container", container.Name, "details", fmt.Sprintf("port: %d", port.HostPort))
					if accepted, justification := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels, port.HostPort); accepted {
						msg := cmp.Or(justification, "Pod accepted to have containers using hostPort < 1024.")
						podCheckResults = append(podCheckResults, rule.AcceptedCheckResult(msg, containertTarget))
					} else {
						podCheckResults = append(podCheckResults, rule.FailedCheckResult("Pod has container using hostPort < 1024.", containertTarget))
					}
				}
			}
		}
		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not have container using hostPort < 1024.", target))
		}
		checkResults = append(checkResults, podCheckResults...)
	}
	return checkResults
}

func (r *Rule242414) accepted(podLabels, namespaceLabels map[string]string, hostPort int32) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if utils.MatchLabels(podLabels, acceptedPod.PodMatchLabels) &&
			utils.MatchLabels(namespaceLabels, acceptedPod.NamespaceMatchLabels) {
			for _, acceptedHostPort := range acceptedPod.Ports {
				if acceptedHostPort == hostPort {
					return true, acceptedPod.Justification
				}
			}
		}
	}

	return false, ""
}
