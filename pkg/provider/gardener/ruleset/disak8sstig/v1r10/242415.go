// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242415{}

type Rule242415 struct {
	ClusterClient         client.Client
	ControlPlaneClient    client.Client
	ControlPlaneNamespace string
	Logger                *slog.Logger
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

	checkResults := r.checkPods(seedPods, seedTarget)

	shootPods, err := kubeutils.GetPods(ctx, r.ClusterClient, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("namespace", r.ControlPlaneNamespace, "kind", "podList"))), nil
	}

	checkResults = append(checkResults, r.checkPods(shootPods, shootTarget)...)

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (*Rule242415) checkPods(pods []corev1.Pod, clusterTarget gardener.Target) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
	for _, pod := range pods {
		target := clusterTarget.With("name", pod.Name, "namespace", pod.Namespace, "kind", "pod")
		passed := true
		for _, container := range pod.Spec.Containers {
			if container.Ports != nil && container.Env != nil {
				for _, env := range container.Env {
					if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
						target = target.With("details", fmt.Sprintf("containerName: %s, keyRef: %s", container.Name, env.ValueFrom.SecretKeyRef.Key))
						checkResults = append(checkResults, rule.FailedCheckResult("Pod uses environment to inject secret.", target))
						passed = false
					}
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
