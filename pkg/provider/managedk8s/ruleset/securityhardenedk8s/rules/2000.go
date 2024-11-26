// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule2000{}
	_ rule.Severity = &Rule2000{}
)

type Rule2000 struct {
	Client client.Client
}

func (r *Rule2000) ID() string {
	return "2000"
}

func (r *Rule2000) Name() string {
	return "Ingress and egress traffic must be restricted by default."
}

func (r *Rule2000) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule2000) Run(ctx context.Context) (rule.RuleResult, error) {
	var checkResults []rule.CheckResult

	networkPolicies, err := kubeutils.GetNetworkPolicies(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "serviceList"))), nil
	}

	namespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "namespaceList"))), nil
	}

	groupedNetworkPolicies := map[string][]networkingv1.NetworkPolicy{}

	for _, np := range networkPolicies {
		groupedNetworkPolicies[np.Namespace] = append(groupedNetworkPolicies[np.Namespace], np)
	}

	for _, namespace := range namespaces {
		var (
			deniesIngress bool
			deniesEgress  bool
			target        = rule.NewTarget("namespace", namespace.Name)
		)

		for _, networkPolicy := range groupedNetworkPolicies[namespace.Name] {
			if len(networkPolicy.Spec.PodSelector.MatchLabels) > 0 ||
				len(networkPolicy.Spec.PodSelector.MatchExpressions) > 0 {
				continue
			}

			if len(networkPolicy.Spec.Ingress) == 0 &&
				slices.Contains(networkPolicy.Spec.PolicyTypes, networkingv1.PolicyTypeIngress) {
				deniesIngress = true
			}

			if len(networkPolicy.Spec.Egress) == 0 &&
				slices.Contains(networkPolicy.Spec.PolicyTypes, networkingv1.PolicyTypeEgress) {
				deniesEgress = true
			}
		}

		switch {
		case deniesIngress && deniesEgress:
			checkResults = append(checkResults, rule.PassedCheckResult("Ingress and egress traffic denied by default.", target))
		case !deniesIngress && !deniesEgress:
			checkResults = append(checkResults, rule.FailedCheckResult("Ingress and egress traffic not denied by default.", target))
		case deniesIngress:
			checkResults = append(checkResults, rule.PassedCheckResult("Ingress traffic denied by default.", target),
				rule.FailedCheckResult("Egress traffic not denied by default.", target))
		default:
			checkResults = append(checkResults, rule.PassedCheckResult("Egress traffic denied by default.", target),
				rule.FailedCheckResult("Ingress traffic not denied by default.", target))
		}
	}

	return rule.Result(r, checkResults...), nil
}
