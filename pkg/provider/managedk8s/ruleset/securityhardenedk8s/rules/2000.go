// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule     = &Rule2000{}
	_ rule.Severity = &Rule2000{}
	_ option.Option = &Options2000{}
)

var (
	timeNow   = time.Now
	timeSleep = func(ctx context.Context, d time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
			return nil
		}
	}
)

const (
	youngNamespaceThreshold = 1 * time.Minute
	maxRetries              = 3
	retryBaseInterval       = 10 * time.Second
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

// Validate validates that option configurations are correctly defined.
func (o Options2000) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedNamespacesPath := fldPath.Child("acceptedNamespaces")
	for nIdx, n := range o.AcceptedNamespaces {
		allErrs = append(allErrs, n.Validate(acceptedNamespacesPath.Index(nIdx))...)
	}

	return allErrs
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
	namespacesMap, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "NamespaceList"))), nil
	}
	namespaces := make([]corev1.Namespace, 0, len(namespacesMap))
	for _, ns := range namespacesMap {
		namespaces = append(namespaces, ns)
	}

	groupedNetworkPolicies, err := r.getGroupedNetworkPolicies(ctx)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "NetworkPolicyList"))), nil
	}

	checkResults, youngFailedNamespaces := r.checkNamespaces(ctx, namespaces, groupedNetworkPolicies, true)
	if len(youngFailedNamespaces) == 0 {
		return rule.Result(r, checkResults...), nil
	}

	for retry := range maxRetries {
		// Sleep for an incremented interval
		if err := timeSleep(ctx, retryBaseInterval*time.Duration(retry+1)); err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
		}

		groupedNetworkPolicies, err = r.getGroupedNetworkPolicies(ctx)
		if err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "NetworkPolicyList"))), nil
		}

		if retry < maxRetries-1 {
			var retryResults []rule.CheckResult
			retryResults, youngFailedNamespaces = r.checkNamespaces(ctx, youngFailedNamespaces, groupedNetworkPolicies, true)
			checkResults = append(checkResults, retryResults...)
			if len(youngFailedNamespaces) == 0 {
				break
			}
		} else {
			retryResults, _ := r.checkNamespaces(ctx, youngFailedNamespaces, groupedNetworkPolicies, false)
			checkResults = append(checkResults, retryResults...)
		}
	}

	return rule.Result(r, checkResults...), nil
}

// checkNamespaces evaluates network policies for the given namespaces. When retryYoung is true,
// namespaces created within the last 1 minute that fail checks are excluded from checkResults
// and returned separately for a retry. When retryYoung is false, all results are included.
func (r *Rule2000) checkNamespaces(ctx context.Context, namespaces []corev1.Namespace, groupedNetworkPolicies map[string][]networkingv1.NetworkPolicy, retryYoung bool) ([]rule.CheckResult, []corev1.Namespace) {
	const (
		namespaceDeletionWithoutPodsDetails = "namespace is marked for deletion without any present pods"
		namespaceDeletionWithPodsDetails    = "namespace is marked for deletion with present pods"
		ingressTrafficNotDeniedMessage      = "Ingress traffic is not denied by default."
		egressTrafficNotDeniedMessage       = "Egress traffic is not denied by default."
	)

	var (
		checkResults          []rule.CheckResult
		youngFailedNamespaces []corev1.Namespace
		now                   = timeNow()
	)

	for _, namespace := range namespaces {
		var (
			deniesAllIngress, deniesAllEgress bool
			allowsAllIngress, allowsAllEgress bool
			target                            = rule.NewTarget("namespace", namespace.Name)
			deniesAllIngressTarget            = target
			deniesAllEgressTarget             = target
			allowsAllIngressTarget            = target
			allowsAllEgressTarget             = target
			nsCheckResults                    []rule.CheckResult
			nsFailed                          bool
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
			nsCheckResults = append(nsCheckResults, rule.PassedCheckResult("Ingress traffic is denied by default.", deniesAllIngressTarget))
		} else {
			accepted, justification, err := r.acceptedIngress(namespace.Labels)
			if err != nil {
				return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), rule.NewTarget())}, nil
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
				nsCheckResults = append(nsCheckResults, rule.AcceptedCheckResult(msg, acceptedTarget))
			case allowsAllIngress:
				nsCheckResults = append(nsCheckResults, rule.FailedCheckResult("All Ingress traffic is allowed by default.", allowsAllIngressTarget))
			case namespace.DeletionTimestamp == nil:
				nsCheckResults = append(nsCheckResults, rule.FailedCheckResult(ingressTrafficNotDeniedMessage, target))
				nsFailed = true
			default:
				pods, err := kubeutils.GetPods(ctx, r.Client, namespace.Name, labels.NewSelector(), 300)
				if err != nil {
					return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), target)}, nil
				}

				if len(pods) > 0 {
					nsCheckResults = append(nsCheckResults, rule.FailedCheckResult(ingressTrafficNotDeniedMessage, target.With("details", namespaceDeletionWithPodsDetails)))
				} else {
					nsCheckResults = append(nsCheckResults, rule.WarningCheckResult(ingressTrafficNotDeniedMessage, target.With("details", namespaceDeletionWithoutPodsDetails)))
				}
			}
		}

		if deniesAllEgress && !allowsAllEgress {
			nsCheckResults = append(nsCheckResults, rule.PassedCheckResult("Egress traffic is denied by default.", deniesAllEgressTarget))
		} else {
			accepted, justification, err := r.acceptedEgress(namespace.Labels)
			if err != nil {
				return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), rule.NewTarget())}, nil
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
				nsCheckResults = append(nsCheckResults, rule.AcceptedCheckResult(msg, acceptedTarget))
			case allowsAllEgress:
				nsCheckResults = append(nsCheckResults, rule.FailedCheckResult("All Egress traffic is allowed by default.", allowsAllEgressTarget))
			case namespace.DeletionTimestamp == nil:
				nsCheckResults = append(nsCheckResults, rule.FailedCheckResult(egressTrafficNotDeniedMessage, target))
				nsFailed = true
			default:
				pods, err := kubeutils.GetPods(ctx, r.Client, namespace.Name, labels.NewSelector(), 300)
				if err != nil {
					return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), target)}, nil
				}

				if len(pods) > 0 {
					nsCheckResults = append(nsCheckResults, rule.FailedCheckResult(egressTrafficNotDeniedMessage, target.With("details", namespaceDeletionWithPodsDetails)))
				} else {
					nsCheckResults = append(nsCheckResults, rule.WarningCheckResult(egressTrafficNotDeniedMessage, target.With("details", namespaceDeletionWithoutPodsDetails)))
				}
			}
		}

		if retryYoung && nsFailed && now.Sub(namespace.CreationTimestamp.Time) < youngNamespaceThreshold {
			youngFailedNamespaces = append(youngFailedNamespaces, namespace)
		} else {
			checkResults = append(checkResults, nsCheckResults...)
		}
	}

	return checkResults, youngFailedNamespaces
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

func (r *Rule2000) getGroupedNetworkPolicies(ctx context.Context) (map[string][]networkingv1.NetworkPolicy, error) {
	networkPolicies, err := kubeutils.GetNetworkPolicies(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return nil, err
	}

	groupedNetworkPolicies := map[string][]networkingv1.NetworkPolicy{}
	for _, np := range networkPolicies {
		groupedNetworkPolicies[np.Namespace] = append(groupedNetworkPolicies[np.Namespace], np)
	}

	return groupedNetworkPolicies, nil
}
