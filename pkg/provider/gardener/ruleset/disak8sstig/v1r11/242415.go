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

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242415{}

type Rule242415 struct {
	ClusterClient         client.Client
	ControlPlaneClient    client.Client
	ControlPlaneNamespace string
	Options               *Options242415
	Logger                *slog.Logger
}

type Options242415 struct {
	AcceptedPods []AcceptedPods242415 `json:"acceptedPods" yaml:"acceptedPods"`
}

type AcceptedPods242415 struct {
	PodMatchLabels       map[string]string `json:"podMatchLabels" yaml:"podMatchLabels"`
	NamespaceMatchLabels map[string]string `json:"namespaceMatchLabels" yaml:"namespaceMatchLabels"`
	Justification        string            `json:"justification" yaml:"justification"`
	EnvironmentVariables []string          `json:"environmentVariables" yaml:"environmentVariables "`
}

func (r *Rule242415) ID() string {
	return ID242415
}

func (r *Rule242415) Name() string {
	return "Secrets in Kubernetes must not be stored as environment variables (HIGH 242415)"
}

func (r *Rule242415) Run(ctx context.Context) (rule.RuleResult, error) {
	seedPods, err := kubeutils.GetPods(ctx, r.ControlPlaneClient, r.ControlPlaneNamespace, labels.NewSelector(), 300)
	seedTarget := gardener.NewTarget("cluster", "seed")
	shootTarget := gardener.NewTarget("cluster", "shoot")
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
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("namespace", r.ControlPlaneNamespace, "kind", "podList"))), nil
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

func (r *Rule242415) checkPods(pods []corev1.Pod, namespaces map[string]corev1.Namespace, clusterTarget gardener.Target) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
	for _, pod := range pods {
		target := clusterTarget.With("name", pod.Name, "namespace", pod.Namespace, "kind", "pod")
		passed := true
		for _, container := range pod.Spec.Containers {
			for _, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					target = target.With("details", fmt.Sprintf("containerName: %s, variableName: %s, keyRef: %s", container.Name, env.Name, env.ValueFrom.SecretKeyRef.Key))
					if accepted, justification := r.accepted(pod.Labels, namespaces[pod.Namespace], env.Name); accepted {
						msg := "Pod accepted to use environment to inject secret."
						if justification != "" {
							msg = justification
						}
						checkResults = append(checkResults, rule.AcceptedCheckResult(msg, target))
					} else {
						checkResults = append(checkResults, rule.FailedCheckResult("Pod uses environment to inject secret.", target))
					}
					passed = false
				}
			}
		}
		if passed {
			checkResults = append(checkResults, rule.CheckResult{
				Status:  rule.Passed,
				Message: "Pod does not use environment to inject secret.",
				Target:  target,
			})
		}
	}
	return checkResults
}

func (r *Rule242415) accepted(podLabels map[string]string, namespace corev1.Namespace, environmentVariable string) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if utils.MatchLabels(podLabels, acceptedPod.PodMatchLabels) &&
			utils.MatchLabels(namespace.Labels, acceptedPod.NamespaceMatchLabels) {
			for _, acceptedEnvironmentVariable := range acceptedPod.EnvironmentVariables {
				if acceptedEnvironmentVariable == environmentVariable {
					return true, acceptedPod.Justification
				}
			}
		}
	}

	return false, ""
}
