// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242414{}

type Rule242414 struct {
	ControlPlaneClient    client.Client
	ControlPlaneNamespace string
	ClusterClient         client.Client
	Options               *Options242414
	Logger                *slog.Logger
}

type Options242414 struct {
	AcceptedPods []AcceptedPods242414 `json:"acceptedPods" yaml:"acceptedPods"`
}

type AcceptedPods242414 struct {
	PodMatchLabels       map[string]string `json:"podMatchLabels" yaml:"podMatchLabels"`
	NamespaceMatchLabels map[string]string `json:"namespaceMatchLabels" yaml:"namespaceMatchLabels"`
	Justification        string            `json:"justification" yaml:"justification"`
	Ports                []int32           `json:"ports" yaml:"ports"`
}

func (r *Rule242414) ID() string {
	return ID242414
}

func (r *Rule242414) Name() string {
	return "Kubernetes cluster must use non-privileged host ports for user pods (MEDIUM 242414)"
}

func (r *Rule242414) Run(ctx context.Context) (rule.RuleResult, error) {
	seedPods, err := kubeutils.GetPods(ctx, r.ControlPlaneClient, r.ControlPlaneNamespace, labels.NewSelector(), 300)
	seedTarget := rule.NewTarget("cluster", "seed")
	shootTarget := rule.NewTarget("cluster", "shoot")
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), seedTarget.With("namespace", r.ControlPlaneNamespace, "kind", "podList"))), nil
	}

	seedNamespaces, err := kubeutils.GetNamespaces(ctx, r.ControlPlaneClient)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), seedTarget.With("kind", "namespaceList"))), nil
	}
	checkResults := r.checkPods(seedPods, seedNamespaces, seedTarget)

	shootPods, err := kubeutils.GetPods(ctx, r.ClusterClient, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.RuleResult{
			RuleID:       r.ID(),
			RuleName:     r.Name(),
			CheckResults: append(checkResults, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "podList"))),
		}, nil
	}

	shootNamespaces, err := kubeutils.GetNamespaces(ctx, r.ClusterClient)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "namespaceList"))), nil
	}
	checkResults = append(checkResults, r.checkPods(shootPods, shootNamespaces, shootTarget)...)

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (r *Rule242414) checkPods(pods []corev1.Pod, namespaces map[string]corev1.Namespace, clusterTarget rule.Target) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
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
