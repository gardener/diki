// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"log/slog"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242417{}

type Rule242417 struct {
	Client client.Client
	Logger *slog.Logger
}

func (r *Rule242417) ID() string {
	return ID242417
}

func (r *Rule242417) Name() string {
	return "Kubernetes must separate user functionality (MEDIUM 242417)"
}

func (r *Rule242417) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}
	systemNamespaces := []string{"kube-system", "kube-public", "kube-node-lease"}

	shootTarget := gardener.NewTarget("cluster", "shoot")
	notManagedByGardenerReq, err := labels.NewRequirement(resourcesv1alpha1.ManagedBy, selection.NotEquals, []string{"gardener"})
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), gardener.NewTarget())), nil
	}

	notDikiPodReq, err := labels.NewRequirement(gardener.LabelComplianceRoleKey, selection.NotEquals, []string{gardener.LabelComplianceRolePrivPod})
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), gardener.NewTarget())), nil
	}
	for _, namespace := range systemNamespaces {
		selector := labels.NewSelector().Add(*notManagedByGardenerReq).Add(*notDikiPodReq)
		podsPartialMetadata, err := kubeutils.GetObjectsMetadata(ctx, r.Client, corev1.SchemeGroupVersion.WithKind("PodList"), namespace, selector, 300)
		if err != nil {
			return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("namespace", namespace, "kind", "podList"))), nil
		}

		for _, podPartialMetadata := range podsPartialMetadata {
			target := shootTarget.With("name", podPartialMetadata.Name, "namespace", podPartialMetadata.Namespace, "kind", "pod")
			checkResults = append(checkResults, rule.FailedCheckResult("Found user pods in system namespaces.", target))
		}
	}

	if len(checkResults) == 0 {
		checkResults = append(checkResults, rule.PassedCheckResult("Found no user pods in system namespaces.", shootTarget))
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
