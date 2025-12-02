// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

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
	const (
		namespaceDeletionWithoutPodsDetails = "namespace is marked for deletion without any present pods"
		namespaceDeletionWithPodsDetails    = "namespace is marked for deletion with present pods"
		ingressTrafficNotDeniedMessage      = "Ingress traffic is not denied by default."
		egressTrafficNotDeniedMessage       = "Egress traffic is not denied by default."
	)

	networkPolicies, err := kubeutils.GetNetworkPolicies(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "ServiceList"))), nil
	}

	namespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "NamespaceList"))), nil
	}

	groupedNetworkPolicies := map[string][]networkingv1.NetworkPolicy{}

	for _, np := range networkPolicies {
		groupedNetworkPolicies[np.Namespace] = append(groupedNetworkPolicies[np.Namespace], np)
	}

	var checkResults []rule.CheckResult

	for _, namespace := range namespaces {

		var (
			deniesAllIngress, deniesAllEgress bool
			allowsAllIngress, allowsAllEgress bool
			target                            = rule.NewTarget("namespace", namespace.Name)
			deniesAllIngressTarget            = target
			deniesAllEgressTarget             = target
			allowsAllIngressTarget            = target
			allowsAllEgressTarget             = target
		)

		for _, networkPolicy := range groupedNetworkPolicies[namespace.Name] {
			if len(networkPolicy.Spec.PodSelector.MatchLabels) > 0 ||
				len(networkPolicy.Spec.PodSelector.MatchExpressions) > 0 {
				continue
			}

			if !deniesAllIngress && len(networkPolicy.Spec.Ingress) == 0 &&
				slices.Contains(networkPolicy.Spec.PolicyTypes, networkingv1.PolicyTypeIngress) {
				deniesAllIngressTarget = kubeutils.TargetWithK8sObject(deniesAllIngressTarget, metav1.TypeMeta{Kind: "NetworkPolicy"}, networkPolicy.ObjectMeta)
				deniesAllIngress = true
			}

			if !allowsAllIngress && slices.ContainsFunc(networkPolicy.Spec.Ingress, func(ingress networkingv1.NetworkPolicyIngressRule) bool {
				return len(ingress.From) == 0 && len(ingress.Ports) == 0
			}) && slices.Contains(networkPolicy.Spec.PolicyTypes, networkingv1.PolicyTypeIngress) {
				allowsAllIngressTarget = kubeutils.TargetWithK8sObject(allowsAllIngressTarget, metav1.TypeMeta{Kind: "NetworkPolicy"}, networkPolicy.ObjectMeta)
				allowsAllIngress = true
			}

			if !deniesAllEgress && len(networkPolicy.Spec.Egress) == 0 &&
				slices.Contains(networkPolicy.Spec.PolicyTypes, networkingv1.PolicyTypeEgress) {
				deniesAllEgressTarget = kubeutils.TargetWithK8sObject(deniesAllEgressTarget, metav1.TypeMeta{Kind: "NetworkPolicy"}, networkPolicy.ObjectMeta)
				deniesAllEgress = true
			}

			if !allowsAllEgress && slices.ContainsFunc(networkPolicy.Spec.Egress, func(egress networkingv1.NetworkPolicyEgressRule) bool {
				return len(egress.To) == 0 && len(egress.Ports) == 0
			}) && slices.Contains(networkPolicy.Spec.PolicyTypes, networkingv1.PolicyTypeEgress) {
				allowsAllEgressTarget = kubeutils.TargetWithK8sObject(allowsAllEgressTarget, metav1.TypeMeta{Kind: "NetworkPolicy"}, networkPolicy.ObjectMeta)
				allowsAllEgress = true
			}

			if allowsAllIngress && allowsAllEgress {
				break
			}
		}

		if deniesAllIngress && !allowsAllIngress {
			checkResults = append(checkResults, rule.PassedCheckResult("Ingress traffic is denied by default.", deniesAllIngressTarget))
		} else {
			accepted, justification, err := r.acceptedIngress(namespace.Labels)
			if err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}

			acceptedTarget := target
			msg := "Namespace is accepted to allow Ingress traffic by default."
			if len(justification) > 0 {
				msg = justification
				// We cannot guarantee that the user has specified in his justification the
				// accepted traffic type. To avoid confusion and duplication of checkResults
				// we specify the traffic type in the target details only for this case.
				acceptedTarget = target.With("details", "traffic: ingress")
			}

			switch {
			case accepted:
				checkResults = append(checkResults, rule.AcceptedCheckResult(msg, acceptedTarget))
			case allowsAllIngress:
				checkResults = append(checkResults, rule.FailedCheckResult("All Ingress traffic is allowed by default.", allowsAllIngressTarget))
			case namespace.DeletionTimestamp == nil:
				checkResults = append(checkResults, rule.FailedCheckResult(ingressTrafficNotDeniedMessage, target))
			default:
				pods, err := kubeutils.GetPods(ctx, r.Client, namespace.Name, labels.NewSelector(), 300)
				if err != nil {
					return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
				}

				if len(pods) > 0 {
					checkResults = append(checkResults, rule.FailedCheckResult(ingressTrafficNotDeniedMessage, target.With("details", namespaceDeletionWithPodsDetails)))
				} else {
					checkResults = append(checkResults, rule.WarningCheckResult(ingressTrafficNotDeniedMessage, target.With("details", namespaceDeletionWithoutPodsDetails)))
				}
			}
		}

		if deniesAllEgress && !allowsAllEgress {
			checkResults = append(checkResults, rule.PassedCheckResult("Egress traffic is denied by default.", deniesAllEgressTarget))
		} else {
			accepted, justification, err := r.acceptedEgress(namespace.Labels)
			if err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}

			acceptedTarget := target
			msg := "Namespace is accepted to allow Egress traffic by default."
			if len(justification) > 0 {
				msg = justification
				// We cannot guarantee that the user has specified in his justification the
				// accepted traffic type. To avoid confusion and duplication of checkResults
				// we specify the traffic type in the target details only for this case.
				acceptedTarget = target.With("details", "traffic: egress")
			}

			switch {
			case accepted:
				checkResults = append(checkResults, rule.AcceptedCheckResult(msg, acceptedTarget))
			case allowsAllEgress:
				checkResults = append(checkResults, rule.FailedCheckResult("All Egress traffic is allowed by default.", allowsAllEgressTarget))
			case namespace.DeletionTimestamp == nil:
				checkResults = append(checkResults, rule.FailedCheckResult(egressTrafficNotDeniedMessage, target))
			default:
				pods, err := kubeutils.GetPods(ctx, r.Client, namespace.Name, labels.NewSelector(), 300)
				if err != nil {
					return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
				}

				if len(pods) > 0 {
					checkResults = append(checkResults, rule.FailedCheckResult(egressTrafficNotDeniedMessage, target.With("details", namespaceDeletionWithPodsDetails)))
				} else {
					checkResults = append(checkResults, rule.WarningCheckResult(egressTrafficNotDeniedMessage, target.With("details", namespaceDeletionWithoutPodsDetails)))
				}
			}
		}
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule2000) acceptedIngress(namespaceLabels map[string]string) (bool, string, error) {
	if r.Options == nil {
		return false, "", nil
	}

	for _, acceptedNamespace := range r.Options.AcceptedNamespaces {
		if matches, err := acceptedNamespace.Matches(namespaceLabels); err != nil {
			return false, "", err
		} else if matches && acceptedNamespace.AcceptedTraffic.Ingress {
			return true, acceptedNamespace.Justification, nil
		}
	}

	return false, "", nil
}

func (r *Rule2000) acceptedEgress(namespaceLabels map[string]string) (bool, string, error) {
	if r.Options == nil {
		return false, "", nil
	}

	for _, acceptedNamespace := range r.Options.AcceptedNamespaces {
		if matches, err := acceptedNamespace.Matches(namespaceLabels); err != nil {
			return false, "", err
		} else if matches && acceptedNamespace.AcceptedTraffic.Egress {
			return true, acceptedNamespace.Justification, nil
		}
	}

	return false, "", nil
}
