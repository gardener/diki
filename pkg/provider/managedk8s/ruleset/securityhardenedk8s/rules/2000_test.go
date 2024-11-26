// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s/rules"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#2000", func() {
	var (
		client client.Client
		ctx    = context.TODO()
	)

	BeforeEach(func() {
		client = fakeclient.NewClientBuilder().Build()
	})

	It("should return correct results", func() {
		r := &rules.Rule2000{Client: client}

		nsDefault := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
		}

		npDefault := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deny-all",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PolicyTypes: []networkingv1.PolicyType{
					"Ingress",
					"Egress",
				},
			},
		}
		Expect(client.Create(ctx, nsDefault)).To(Succeed())
		Expect(client.Create(ctx, npDefault)).To(Succeed())

		nsSystem := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kube-system",
			},
		}

		npSystem := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deny-ingress",
				Namespace: "kube-system",
			},
			Spec: networkingv1.NetworkPolicySpec{
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{
					"Ingress",
					"Egress",
				},
			},
		}
		Expect(client.Create(ctx, nsSystem)).To(Succeed())
		Expect(client.Create(ctx, npSystem)).To(Succeed())

		nsPublic := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kube-public",
			},
		}

		npPublic1 := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deny-egress",
				Namespace: "kube-public",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PolicyTypes: []networkingv1.PolicyType{
					"Egress",
				},
			},
		}
		npPublic2 := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "not-deny-ingress",
				Namespace: "kube-public",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"foo": "bar",
					},
				},
				PolicyTypes: []networkingv1.PolicyType{
					"Ingress",
				},
			},
		}
		Expect(client.Create(ctx, nsPublic)).To(Succeed())
		Expect(client.Create(ctx, npPublic1)).To(Succeed())
		Expect(client.Create(ctx, npPublic2)).To(Succeed())

		nsLease := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kube-node-lease",
			},
		}

		Expect(client.Create(ctx, nsLease)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Ingress and egress traffic denied by default.",
				Target:  rule.NewTarget("namespace", "default"),
			},
			{
				Status:  rule.Passed,
				Message: "Ingress traffic denied by default.",
				Target:  rule.NewTarget("namespace", "kube-system"),
			},
			{
				Status:  rule.Failed,
				Message: "Egress traffic not denied by default.",
				Target:  rule.NewTarget("namespace", "kube-system"),
			},
			{
				Status:  rule.Passed,
				Message: "Egress traffic denied by default.",
				Target:  rule.NewTarget("namespace", "kube-public"),
			},
			{
				Status:  rule.Failed,
				Message: "Ingress traffic not denied by default.",
				Target:  rule.NewTarget("namespace", "kube-public"),
			},
			{
				Status:  rule.Failed,
				Message: "Ingress and egress traffic not denied by default.",
				Target:  rule.NewTarget("namespace", "kube-node-lease"),
			},
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})
})
