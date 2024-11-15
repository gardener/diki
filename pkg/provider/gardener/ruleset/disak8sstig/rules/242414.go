// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
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
	seedPods, err := kubeutils.GetPods(ctx, r.ControlPlaneClient, r.ControlPlaneNamespace, labels.NewSelector(), 300)
	seedTarget := rule.NewTarget("cluster", "seed")
	shootTarget := rule.NewTarget("cluster", "shoot")
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
		return rule.Result(r, append(checkResults, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "podList")))...), nil
	}

	shootNamespaces, err := kubeutils.GetNamespaces(ctx, r.ClusterClient)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "namespaceList"))), nil
	}
	checkResults = append(checkResults, r.checkPods(shootPods, shootNamespaces, shootTarget)...)

	return rule.Result(r, checkResults...), nil
}

func (r *Rule242414) checkPods(pods []corev1.Pod, namespaces map[string]corev1.Namespace, clusterTarget rule.Target) []rule.CheckResult {
	var checkResults []rule.CheckResult
	for _, pod := range pods {
		target := clusterTarget.With("name", pod.Name, "namespace", pod.Namespace, "kind", "pod")
		for _, container := range pod.Spec.Containers {
			uses := false
			for _, port := range container.Ports {
				if port.HostPort != 0 && port.HostPort < 1024 {
					target = target.With("details", fmt.Sprintf("containerName: %s, port: %d", container.Name, port.HostPort))
					if accepted, justification := r.accepted(pod, namespaces[pod.Namespace], port.HostPort); accepted {
						msg := "Container accepted to use hostPort < 1024."
						if justification != "" {
							msg = justification
						}
						checkResults = append(checkResults, rule.AcceptedCheckResult(msg, target))
					} else {
						checkResults = append(checkResults, rule.FailedCheckResult("Container may not use hostPort < 1024.", target))
					}
					uses = true
				}
			}
			if !uses {
				checkResults = append(checkResults, rule.PassedCheckResult("Container does not use hostPort < 1024.", target))
			}
		}
	}
	return checkResults
}

func (r *Rule242414) accepted(pod corev1.Pod, namespace corev1.Namespace, hostPort int32) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if utils.MatchLabels(pod.Labels, acceptedPod.PodMatchLabels) &&
			utils.MatchLabels(namespace.Labels, acceptedPod.NamespaceMatchLabels) {
			for _, acceptedHostPort := range acceptedPod.Ports {
				if acceptedHostPort == hostPort {
					return true, acceptedPod.Justification
				}
			}
		}
	}

	return false, ""
}
