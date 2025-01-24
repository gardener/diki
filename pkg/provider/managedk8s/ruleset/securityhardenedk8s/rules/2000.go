// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule     = &Rule2000{}
	_ rule.Severity = &Rule2000{}
)

type Rule2000 struct {
	Client  client.Client
	Options *Options2000
}

type Options2000 struct {
	AcceptedNamespaces []AcceptedNamespaces2000 `json:"acceptedNamespaces" yaml:"acceptedNamespaces"`
}

type AcceptedNamespaces2000 struct {
	option.AcceptedClusterObject
	AcceptedTraffic AcceptedTraffic `json:"acceptedTraffic" yaml:"acceptedTraffic"`
}

type AcceptedTraffic struct {
	Egress  bool `json:"egress" yaml:"egress"`
	Ingress bool `json:"ingress" yaml:"ingress"`
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

	var checkResults []rule.CheckResult

	for _, namespace := range namespaces {
		var (
			deniesIngress, deniesEgress bool
			target                      = rule.NewTarget("namespace", namespace.Name)
			deniesIngressTarget         = target
			deniesEgressTarget          = target
		)

		for _, networkPolicy := range groupedNetworkPolicies[namespace.Name] {
			if len(networkPolicy.Spec.PodSelector.MatchLabels) > 0 ||
				len(networkPolicy.Spec.PodSelector.MatchExpressions) > 0 {
				continue
			}

			if !deniesIngress && len(networkPolicy.Spec.Ingress) == 0 &&
				slices.Contains(networkPolicy.Spec.PolicyTypes, networkingv1.PolicyTypeIngress) {
				deniesIngressTarget = deniesIngressTarget.With("kind", "networkPolicy", "name", networkPolicy.Name)
				deniesIngress = true
			}

			if !deniesEgress && len(networkPolicy.Spec.Egress) == 0 &&
				slices.Contains(networkPolicy.Spec.PolicyTypes, networkingv1.PolicyTypeEgress) {
				deniesEgressTarget = deniesEgressTarget.With("kind", "networkPolicy", "name", networkPolicy.Name)
				deniesEgress = true
			}

			if deniesIngress && deniesEgress {
				break
			}
		}

		if deniesIngress {
			checkResults = append(checkResults, rule.PassedCheckResult("Ingress traffic is denied by default.", deniesIngressTarget))
		} else {
			accepted, justification := r.acceptedIngress(namespace)

			acceptedTarget := target
			msg := "Namespace is accepted to allow Ingress traffic by default."
			if len(justification) > 0 {
				msg = justification
				// We cannot guarantee that the user has specified in his justification the
				// accepted traffic type. To avoid confusion and duplication of checkResults
				// we specify the traffic type in the target details only for this case.
				acceptedTarget = target.With("details", "traffic: ingress")
			}

			if accepted {
				checkResults = append(checkResults, rule.AcceptedCheckResult(msg, acceptedTarget))
			} else {
				checkResults = append(checkResults, rule.FailedCheckResult("Ingress traffic is not denied by default.", target))
			}
		}

		if deniesEgress {
			checkResults = append(checkResults, rule.PassedCheckResult("Egress traffic is denied by default.", deniesEgressTarget))
		} else {
			accepted, justification := r.acceptedEgress(namespace)

			acceptedTarget := target
			msg := "Namespace is accepted to allow Egress traffic by default."
			if len(justification) > 0 {
				msg = justification
				// We cannot guarantee that the user has specified in his justification the
				// accepted traffic type. To avoid confusion and duplication of checkResults
				// we specify the traffic type in the target details only for this case.
				acceptedTarget = target.With("details", "traffic: egress")
			}

			if accepted {
				checkResults = append(checkResults, rule.AcceptedCheckResult(msg, acceptedTarget))
			} else {
				checkResults = append(checkResults, rule.FailedCheckResult("Egress traffic is not denied by default.", target))
			}
		}
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule2000) acceptedIngress(namespace corev1.Namespace) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedNamespace := range r.Options.AcceptedNamespaces {

		if utils.MatchLabels(namespace.Labels, acceptedNamespace.MatchLabels) &&
			acceptedNamespace.AcceptedTraffic.Ingress {
			return true, acceptedNamespace.Justification
		}
	}

	return false, ""
}

func (r *Rule2000) acceptedEgress(namespace corev1.Namespace) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedNamespace := range r.Options.AcceptedNamespaces {
		if utils.MatchLabels(namespace.Labels, acceptedNamespace.MatchLabels) &&
			acceptedNamespace.AcceptedTraffic.Egress {
			return true, acceptedNamespace.Justification
		}
	}

	return false, ""
}
