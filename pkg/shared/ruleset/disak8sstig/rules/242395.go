// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule242395{}
	_ rule.Severity = &Rule242395{}
)

type Rule242395 struct {
	Client client.Client
}

func (r *Rule242395) ID() string {
	return ID242395
}

func (r *Rule242395) Name() string {
	return "Kubernetes dashboard must not be enabled."
}

func (r *Rule242395) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242395) Run(ctx context.Context) (rule.RuleResult, error) {
	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.SelectorFromSet(labels.Set{"k8s-app": "kubernetes-dashboard"}), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "PodList"))), nil
	}
	filteredPods := kubeutils.FilterPodsByOwnerRef(pods)

	replicaSets, err := kubeutils.GetReplicaSets(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "ReplicaSetList"))), nil
	}

	var checkResults []rule.CheckResult
	for _, pod := range filteredPods {
		target := kubeutils.TargetWithPod(rule.NewTarget(), pod, replicaSets)
		checkResults = append(checkResults, rule.FailedCheckResult("Kubernetes dashboard installed", target))
	}

	if len(checkResults) == 0 {
		return rule.Result(r, rule.PassedCheckResult("Kubernetes dashboard not installed", rule.NewTarget())), nil
	}

	return rule.Result(r, checkResults...), nil
}
