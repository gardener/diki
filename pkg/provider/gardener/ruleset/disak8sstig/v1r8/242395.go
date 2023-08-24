// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242395{}

type Rule242395 struct {
	Client client.Client
	Logger *slog.Logger
}

func (r *Rule242395) ID() string {
	return ID242395
}

func (r *Rule242395) Name() string {
	return "Kubernetes dashboard must not be enabled (MEDIUM 242395)"
}

func (r *Rule242395) Run(ctx context.Context) (rule.RuleResult, error) {
	shootTarget := gardener.NewTarget("cluster", "shoot")
	podsPartialMetadata, err := utils.GetObjectsMetadata(ctx, r.Client, corev1.SchemeGroupVersion.WithKind("PodList"), "", labels.SelectorFromSet(labels.Set{"k8s-app": "kubernetes-dashboard"}), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "podList"))), nil
	}

	checkResults := []rule.CheckResult{}
	for _, podPartialMetadata := range podsPartialMetadata {
		target := shootTarget.With("name", podPartialMetadata.Name, "namespace", podPartialMetadata.Namespace, "kind", "pod")
		checkResults = append(checkResults, rule.FailedCheckResult("Kubernetes dashboard installed", target))
	}

	if len(checkResults) == 0 {
		return rule.SingleCheckResult(r, rule.PassedCheckResult("Kubernetes dashboard not installed", shootTarget)), nil
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
