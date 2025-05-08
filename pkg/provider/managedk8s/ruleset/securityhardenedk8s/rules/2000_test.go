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
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
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
		options := &rules.Options2000{
			AcceptedNamespaces: []rules.AcceptedNamespaces2000{
				{
					AcceptedClusterObject: option.AcceptedClusterObject{
						ClusterObjectSelector: option.ClusterObjectSelector{
							MatchLabels: map[string]string{
								"ns": "lease",
							},
						},
					},
					AcceptedTraffic: rules.AcceptedTraffic{
						Egress: true,
					},
				},
				{
					AcceptedClusterObject: option.AcceptedClusterObject{
						ClusterObjectSelector: option.ClusterObjectSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
						Justification: "justification foo",
					},
					AcceptedTraffic: rules.AcceptedTraffic{
						Egress:  true,
						Ingress: true,
					},
				},
				{
					AcceptedClusterObject: option.AcceptedClusterObject{
						ClusterObjectSelector: option.ClusterObjectSelector{
							MatchLabels: map[string]string{
								"role": "test1",
							},
						},
						Justification: "justification test",
					},
					AcceptedTraffic: rules.AcceptedTraffic{
						Egress: true,
					},
				},
				{
					AcceptedClusterObject: option.AcceptedClusterObject{
						ClusterObjectSelector: option.ClusterObjectSelector{
							MatchLabels: map[string]string{
								"role": "test4",
							},
						},
						Justification: "justification test 4",
					},
					AcceptedTraffic: rules.AcceptedTraffic{
						Ingress: true,
					},
				},
			},
		}

		r := &rules.Rule2000{Client: client, Options: options}

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
				Labels: map[string]string{
					"ns": "lease",
				},
			},
		}

		Expect(client.Create(ctx, nsLease)).To(Succeed())

		nsFoo := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kube-foo",
				Labels: map[string]string{
					"foo": "bar",
				},
			},
		}

		Expect(client.Create(ctx, nsFoo)).To(Succeed())

		nsTest1 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test1",
				Labels: map[string]string{
					"role": "test1",
				},
			},
		}

		Expect(client.Create(ctx, nsTest1)).To(Succeed())

		npTest1 := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default-allow",
				Namespace: "test1",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{}},
				Egress:  []networkingv1.NetworkPolicyEgressRule{{}},
			},
		}

		Expect(client.Create(ctx, npTest1)).To(Succeed())

		nsTest2 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test2",
				Labels: map[string]string{
					"role": "test2",
				},
			},
		}

		Expect(client.Create(ctx, nsTest2)).To(Succeed())

		npTest2 := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mixed-allow",
				Namespace: "test2",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{{}},
			},
		}

		Expect(client.Create(ctx, npTest2)).To(Succeed())

		nsTest3 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test3",
				Labels: map[string]string{
					"role": "test3",
				},
			},
		}

		Expect(client.Create(ctx, nsTest3)).To(Succeed())

		npTest3 := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ingress-deny-only",
				Namespace: "test3",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foo": "bar",
									},
								},
							},
						},
					},
				},
			},
		}

		Expect(client.Create(ctx, npTest3)).To(Succeed())

		nsTest4 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test4",
				Labels: map[string]string{
					"role": "test4",
				},
			},
		}

		Expect(client.Create(ctx, nsTest4)).To(Succeed())

		npTest4Allow := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default-allow-egress",
				Namespace: "test4",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeEgress,
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{{}},
			},
		}

		Expect(client.Create(ctx, npTest4Allow)).To(Succeed())

		npTest4Deny := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default-deny-egress",
				Namespace: "test4",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeEgress,
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{},
			},
		}

		Expect(client.Create(ctx, npTest4Deny)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Ingress traffic is denied by default.",
				Target:  rule.NewTarget("namespace", "default", "kind", "networkPolicy", "name", "deny-all"),
			},
			{
				Status:  rule.Passed,
				Message: "Egress traffic is denied by default.",
				Target:  rule.NewTarget("namespace", "default", "kind", "networkPolicy", "name", "deny-all"),
			},
			{
				Status:  rule.Passed,
				Message: "Ingress traffic is denied by default.",
				Target:  rule.NewTarget("namespace", "kube-system", "kind", "networkPolicy", "name", "deny-ingress"),
			},
			{
				Status:  rule.Failed,
				Message: "All Egress traffic is allowed by default.",
				Target:  rule.NewTarget("namespace", "kube-system", "kind", "networkPolicy", "name", "deny-ingress"),
			},
			{
				Status:  rule.Passed,
				Message: "Egress traffic is denied by default.",
				Target:  rule.NewTarget("namespace", "kube-public", "kind", "networkPolicy", "name", "deny-egress"),
			},
			{
				Status:  rule.Failed,
				Message: "Ingress traffic is not denied by default.",
				Target:  rule.NewTarget("namespace", "kube-public"),
			},
			{
				Status:  rule.Failed,
				Message: "Ingress traffic is not denied by default.",
				Target:  rule.NewTarget("namespace", "kube-node-lease"),
			},
			{
				Status:  rule.Accepted,
				Message: "Namespace is accepted to allow Egress traffic by default.",
				Target:  rule.NewTarget("namespace", "kube-node-lease"),
			},
			{
				Status:  rule.Accepted,
				Message: "justification foo",
				Target:  rule.NewTarget("namespace", "kube-foo", "details", "traffic: egress"),
			},
			{
				Status:  rule.Accepted,
				Message: "justification foo",
				Target:  rule.NewTarget("namespace", "kube-foo", "details", "traffic: ingress"),
			},
			{
				Status:  rule.Failed,
				Message: "All Ingress traffic is allowed by default.",
				Target:  rule.NewTarget("namespace", "test1", "kind", "networkPolicy", "name", "default-allow"),
			},
			{
				Status:  rule.Accepted,
				Message: "justification test",
				Target:  rule.NewTarget("namespace", "test1", "details", "traffic: egress"),
			},
			{
				Status:  rule.Passed,
				Message: "Ingress traffic is denied by default.",
				Target:  rule.NewTarget("namespace", "test2", "kind", "networkPolicy", "name", "mixed-allow"),
			},
			{
				Status:  rule.Failed,
				Message: "All Egress traffic is allowed by default.",
				Target:  rule.NewTarget("namespace", "test2", "kind", "networkPolicy", "name", "mixed-allow"),
			},
			{
				Status:  rule.Failed,
				Message: "Egress traffic is not denied by default.",
				Target:  rule.NewTarget("namespace", "test3"),
			},
			{
				Status:  rule.Passed,
				Message: "Ingress traffic is denied by default.",
				Target:  rule.NewTarget("namespace", "test3", "kind", "networkPolicy", "name", "ingress-deny-only"),
			},
			{
				Status:  rule.Accepted,
				Message: "justification test 4",
				Target:  rule.NewTarget("namespace", "test4", "details", "traffic: ingress"),
			},
			{
				Status:  rule.Failed,
				Message: "All Egress traffic is allowed by default.",
				Target:  rule.NewTarget("namespace", "test4", "kind", "networkPolicy", "name", "default-allow-egress"),
			},
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})
})
