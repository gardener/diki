// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"
	"time"

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

	Context("test namespaces without a deletion timestamp", func() {

		var plainNamespace *corev1.Namespace

		BeforeEach(func() {
			plainNamespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "plain-namespace",
				},
			}
			client = fakeclient.NewClientBuilder().Build()
		})

		DescribeTable("test namespaces without a deletion timestamp",
			func(configuredNetworkPolicyName string, configuredNetworkPolicySpec *networkingv1.NetworkPolicySpec, checkResults []rule.CheckResult) {
				Expect(client.Create(ctx, plainNamespace)).To(Succeed())

				configuredNetworkPolicy := &networkingv1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      configuredNetworkPolicyName,
						Namespace: plainNamespace.Name,
					},
					Spec: *configuredNetworkPolicySpec,
				}
				Expect(client.Create(ctx, configuredNetworkPolicy)).To(Succeed())

				r := rules.Rule2000{Client: client}
				ruleResult, err := r.Run(ctx)

				Expect(err).ToNot(HaveOccurred())
				Expect(ruleResult.CheckResults).To(Equal(checkResults))
			},
			Entry("should pass when a deny-all network policy is configured",
				"deny-all",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						networkingv1.PolicyTypeIngress,
						networkingv1.PolicyTypeEgress,
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{},
					Egress:  []networkingv1.NetworkPolicyEgressRule{},
				},
				[]rule.CheckResult{
					{
						Status:  rule.Passed,
						Message: "Ingress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "deny-all"),
					},
					{
						Status:  rule.Passed,
						Message: "Egress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "deny-all"),
					},
				},
			),
			Entry("should fail if an allow-all network policy is configured for ingress explicitly",
				"deny-all",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						networkingv1.PolicyTypeIngress,
						networkingv1.PolicyTypeEgress,
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{{}},
					Egress:  []networkingv1.NetworkPolicyEgressRule{},
				},
				[]rule.CheckResult{
					{
						Status:  rule.Failed,
						Message: "All Ingress traffic is allowed by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "deny-all"),
					},
					{
						Status:  rule.Passed,
						Message: "Egress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "deny-all"),
					},
				},
			),
			Entry("should fail if an allow-all network policy is configured for egress explicitly",
				"deny-all",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						networkingv1.PolicyTypeIngress,
						networkingv1.PolicyTypeEgress,
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{},
					Egress:  []networkingv1.NetworkPolicyEgressRule{{}},
				},
				[]rule.CheckResult{
					{
						Status:  rule.Passed,
						Message: "Ingress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "deny-all"),
					},
					{
						Status:  rule.Failed,
						Message: "All Egress traffic is allowed by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "deny-all"),
					},
				},
			),
			Entry("should fail if no denying network policy is configured for ingress",
				"deny-all",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						networkingv1.PolicyTypeEgress,
					},
					Egress: []networkingv1.NetworkPolicyEgressRule{},
				},
				[]rule.CheckResult{
					{
						Status:  rule.Failed,
						Message: "Ingress traffic is not denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace"),
					},
					{
						Status:  rule.Passed,
						Message: "Egress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "deny-all"),
					},
				}),
			Entry("should fail if no denying network policy is configured for egress",
				"deny-all",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						networkingv1.PolicyTypeIngress,
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{},
				},
				[]rule.CheckResult{
					{
						Status:  rule.Passed,
						Message: "Ingress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "deny-all"),
					},
					{
						Status:  rule.Failed,
						Message: "Egress traffic is not denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace"),
					},
				}),
			Entry("should handle namespace with pod-specific network policy",
				"pod-specific-policy",
				&networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "specific",
						},
					},
					PolicyTypes: []networkingv1.PolicyType{
						networkingv1.PolicyTypeIngress,
					},
				},
				[]rule.CheckResult{
					{
						Status:  rule.Failed,
						Message: "Ingress traffic is not denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace"),
					},
					{
						Status:  rule.Failed,
						Message: "Egress traffic is not denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace"),
					},
				},
			),
			Entry("should handle namespace with targeted egress rules",
				"targeted-egress",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						networkingv1.PolicyTypeIngress,
						networkingv1.PolicyTypeEgress,
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{},
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							To: []networkingv1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"allowed": "true",
										},
									},
								},
							},
						},
					},
				},
				[]rule.CheckResult{
					{
						Status:  rule.Passed,
						Message: "Ingress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "targeted-egress"),
					},
					{
						Status:  rule.Failed,
						Message: "Egress traffic is not denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace"),
					},
				},
			),
		)

		It("should fail when a namespace has no network policies at all", func() {
			testNamespace := plainNamespace.DeepCopy()
			testNamespace.Name = "test"
			Expect(client.Create(ctx, testNamespace)).To(Succeed())

			r := &rules.Rule2000{Client: client}

			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())

			Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
				{
					Status:  rule.Failed,
					Message: "Ingress traffic is not denied by default.",
					Target:  rule.NewTarget("namespace", "test"),
				},
				{
					Status:  rule.Failed,
					Message: "Egress traffic is not denied by default.",
					Target:  rule.NewTarget("namespace", "test"),
				},
			}))
		})

		It("should fail when a namespace has both a deny-all and an allow-all NetworkPolicy configured", func() {
			testNamespace := plainNamespace.DeepCopy()
			testNamespace.Name = "test"
			testNamespace.Labels = map[string]string{
				"role": "test",
			}
			Expect(client.Create(ctx, testNamespace)).To(Succeed())

			allowAllNetworkPolicy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "allow-all",
					Namespace: "test",
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
			Expect(client.Create(ctx, allowAllNetworkPolicy)).To(Succeed())

			denyAllNetworkPolicy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deny-all",
					Namespace: "test",
				},
				Spec: networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						networkingv1.PolicyTypeIngress,
						networkingv1.PolicyTypeEgress,
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{},
					Egress:  []networkingv1.NetworkPolicyEgressRule{},
				},
			}
			Expect(client.Create(ctx, denyAllNetworkPolicy)).To(Succeed())

			ruleOptions := &rules.Options2000{
				AcceptedNamespaces: []rules.AcceptedNamespaces2000{
					{
						AcceptedClusterObject: option.AcceptedClusterObject{
							ClusterObjectSelector: option.ClusterObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"role": "test",
									},
								},
							},
							Justification: "test justification",
						},
						AcceptedTraffic: rules.AcceptedTraffic{
							Ingress: false,
							Egress:  true,
						},
					},
					{
						AcceptedClusterObject: option.AcceptedClusterObject{
							ClusterObjectSelector: option.ClusterObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"role": "not-test",
									},
								},
							},
							Justification: "non-test justification",
						},
						AcceptedTraffic: rules.AcceptedTraffic{
							Ingress: true,
							Egress:  true,
						},
					},
				},
			}

			r := &rules.Rule2000{Client: client, Options: ruleOptions}

			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())

			Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
				{
					Status:  rule.Failed,
					Message: "All Ingress traffic is allowed by default.",
					Target:  rule.NewTarget("namespace", "test", "kind", "NetworkPolicy", "name", "allow-all"),
				},
				{
					Status:  rule.Accepted,
					Message: "test justification",
					Target:  rule.NewTarget("namespace", "test", "details", "traffic: egress"),
				},
			}))
		})

		It("should handle accepted namespaces based on options", func() {
			acceptedNamespace := plainNamespace.DeepCopy()
			acceptedNamespace.Name = "accepted-namespace"
			acceptedNamespace.Labels = map[string]string{
				"environment": "production",
			}
			Expect(client.Create(ctx, acceptedNamespace)).To(Succeed())

			partiallyAcceptedNamespace := plainNamespace.DeepCopy()
			partiallyAcceptedNamespace.Name = "partially-accepted"
			partiallyAcceptedNamespace.Labels = map[string]string{
				"team": "security",
			}
			Expect(client.Create(ctx, partiallyAcceptedNamespace)).To(Succeed())

			allowAllPolicy1 := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "allow-all",
					Namespace: "accepted-namespace",
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
			Expect(client.Create(ctx, allowAllPolicy1)).To(Succeed())

			allowAllPolicy2 := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "allow-all",
					Namespace: "partially-accepted",
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
			Expect(client.Create(ctx, allowAllPolicy2)).To(Succeed())

			ruleOptions := &rules.Options2000{
				AcceptedNamespaces: []rules.AcceptedNamespaces2000{
					{
						AcceptedClusterObject: option.AcceptedClusterObject{
							ClusterObjectSelector: option.ClusterObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"environment": "production",
									},
								},
							},
							Justification: "justification 1",
						},
						AcceptedTraffic: rules.AcceptedTraffic{
							Ingress: true,
							Egress:  true,
						},
					},
					{
						AcceptedClusterObject: option.AcceptedClusterObject{
							ClusterObjectSelector: option.ClusterObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"team": "security",
									},
								},
							},
							Justification: "justification 2",
						},
						AcceptedTraffic: rules.AcceptedTraffic{
							Ingress: false,
							Egress:  true,
						},
					},
				},
			}

			r := &rules.Rule2000{Client: client, Options: ruleOptions}
			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(ConsistOf([]rule.CheckResult{
				{
					Status:  rule.Accepted,
					Message: "justification 1",
					Target:  rule.NewTarget("namespace", "accepted-namespace", "details", "traffic: ingress"),
				},
				{
					Status:  rule.Accepted,
					Message: "justification 1",
					Target:  rule.NewTarget("namespace", "accepted-namespace", "details", "traffic: egress"),
				},
				{
					Status:  rule.Failed,
					Message: "All Ingress traffic is allowed by default.",
					Target:  rule.NewTarget("namespace", "partially-accepted", "kind", "NetworkPolicy", "name", "allow-all"),
				},
				{
					Status:  rule.Accepted,
					Message: "justification 2",
					Target:  rule.NewTarget("namespace", "partially-accepted", "details", "traffic: egress"),
				},
			}))
		})

	})

	Context("test namespaces with deletion timestamp", func() {
		var (
			namespaceWithDeletionTimestamp *corev1.Namespace
			plainPod                       *corev1.Pod
		)

		BeforeEach(func() {
			namespaceWithDeletionTimestamp = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "plain-namespace",
					Labels: map[string]string{
						"ns": "plain",
					},
					DeletionTimestamp: &metav1.Time{Time: time.Now()},
					Finalizers:        []string{"test-finalizer"},
				},
			}
			plainPod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "plain-pod",
					Namespace: "plain-namespace",
				},
			}
		})

		DescribeTable("Run test cases for namespaces with deletion timestamp",
			func(configuredNetworkPolicyName string, configuredNetworkPolicySpec *networkingv1.NetworkPolicySpec, deployPod bool, checkResults []rule.CheckResult) {
				client = fakeclient.NewClientBuilder().WithObjects(namespaceWithDeletionTimestamp).Build()

				configuredNetworkPolicy := &networkingv1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      configuredNetworkPolicyName,
						Namespace: namespaceWithDeletionTimestamp.Name,
					},
					Spec: *configuredNetworkPolicySpec,
				}
				Expect(client.Create(ctx, configuredNetworkPolicy)).To(Succeed())

				if deployPod {
					Expect(client.Create(ctx, plainPod)).To(Succeed())
				}

				r := rules.Rule2000{Client: client}
				ruleResult, err := r.Run(ctx)

				Expect(err).ToNot(HaveOccurred())
				Expect(ruleResult.CheckResults).To(Equal(checkResults))
			},
			Entry("should pass when the namespace has a deny-all network policy configured",
				"deny-all",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						"Ingress",
						"Egress",
					},
				},
				true,
				[]rule.CheckResult{
					{
						Status:  rule.Passed,
						Message: "Ingress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "deny-all"),
					},
					{
						Status:  rule.Passed,
						Message: "Egress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "deny-all"),
					},
				},
			),
			Entry("should fail when an allow-all network policy is configured for ingress and pods are still present",
				"allow-ingress",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						"Ingress",
						"Egress",
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{{}},
				},
				true,
				[]rule.CheckResult{
					{
						Status:  rule.Failed,
						Message: "All Ingress traffic is allowed by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "allow-ingress"),
					},
					{
						Status:  rule.Passed,
						Message: "Egress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "allow-ingress"),
					},
				},
			),
			Entry("should fail when an allow-all network policy is configured for egress and pods are still present",
				"allow-egress",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						"Ingress",
						"Egress",
					},
					Egress: []networkingv1.NetworkPolicyEgressRule{{}},
				},
				true,
				[]rule.CheckResult{
					{
						Status:  rule.Passed,
						Message: "Ingress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "allow-egress"),
					},
					{
						Status:  rule.Failed,
						Message: "All Egress traffic is allowed by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "allow-egress"),
					},
				},
			),
			Entry("should fail when no denying network policy is explicitly set for ingress and pods are present on the namespace",
				"not-deny-ingress",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						"Egress",
					},
					Egress: []networkingv1.NetworkPolicyEgressRule{},
				},
				true,
				[]rule.CheckResult{
					{
						Status:  rule.Failed,
						Message: "Ingress traffic is not denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "details", "namespace is marked for deletion with present pods"),
					},
					{
						Status:  rule.Passed,
						Message: "Egress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "not-deny-ingress"),
					},
				},
			),
			Entry("should fail when no denying network policy is explicitly set for egress and pods are present on the namespace",
				"not-deny-egress",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						"Ingress",
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{},
				},
				true,
				[]rule.CheckResult{
					{
						Status:  rule.Passed,
						Message: "Ingress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "not-deny-egress"),
					},
					{
						Status:  rule.Failed,
						Message: "Egress traffic is not denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "details", "namespace is marked for deletion with present pods"),
					},
				},
			),
			Entry("should fail when an allow-all network policy is configured for the ingress traffic and there are no pods present",
				"allow-ingress",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						"Ingress",
						"Egress",
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{{}},
				},
				false,
				[]rule.CheckResult{
					{
						Status:  rule.Failed,
						Message: "All Ingress traffic is allowed by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "allow-ingress"),
					},
					{
						Status:  rule.Passed,
						Message: "Egress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "allow-ingress"),
					},
				},
			),
			Entry("should fail when an allow-all network policy is configured for the egress traffic and there are no pods present",
				"allow-egress",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						"Ingress",
						"Egress",
					},
					Egress: []networkingv1.NetworkPolicyEgressRule{{}},
				},
				false,
				[]rule.CheckResult{
					{
						Status:  rule.Passed,
						Message: "Ingress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "allow-egress"),
					},
					{
						Status:  rule.Failed,
						Message: "All Egress traffic is allowed by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "allow-egress"),
					},
				},
			),
			Entry("should warn when no denying network policy is configured for ingress and there are no pods present",
				"no-deny-ingress",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						"Egress",
					},
					Egress: []networkingv1.NetworkPolicyEgressRule{},
				},
				false,
				[]rule.CheckResult{
					{
						Status:  rule.Warning,
						Message: "Ingress traffic is not denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "details", "namespace is marked for deletion without any present pods"),
					},
					{
						Status:  rule.Passed,
						Message: "Egress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "no-deny-ingress"),
					},
				},
			),
			Entry("should warn when no denying network policy is configured for egress and there are no pods present",
				"no-deny-egress",
				&networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						"Ingress",
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{},
				},
				false,
				[]rule.CheckResult{
					{
						Status:  rule.Passed,
						Message: "Ingress traffic is denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "kind", "NetworkPolicy", "name", "no-deny-egress"),
					},
					{
						Status:  rule.Warning,
						Message: "Egress traffic is not denied by default.",
						Target:  rule.NewTarget("namespace", "plain-namespace", "details", "namespace is marked for deletion without any present pods"),
					},
				},
			),
		)

		It("should fail when a namespace in deletion has no network policies but still hosts pods", func() {
			testNamespace := namespaceWithDeletionTimestamp.DeepCopy()
			testNamespace.Name = "test"

			client = fakeclient.NewClientBuilder().WithObjects(testNamespace).Build()

			testPod := plainPod.DeepCopy()
			testPod.Namespace = "test"
			Expect(client.Create(ctx, testPod)).To(Succeed())

			r := rules.Rule2000{Client: client}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())

			Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
				{
					Status:  "Failed",
					Message: "Ingress traffic is not denied by default.",
					Target:  rule.NewTarget("namespace", "test", "details", "namespace is marked for deletion with present pods"),
				},
				{
					Status:  "Failed",
					Message: "Egress traffic is not denied by default.",
					Target:  rule.NewTarget("namespace", "test", "details", "namespace is marked for deletion with present pods"),
				},
			}))
		})

		It("should warn when a namespace in deletion has no network policies and doesn't host pods", func() {
			testNamespace := namespaceWithDeletionTimestamp.DeepCopy()
			testNamespace.Name = "test"

			client = fakeclient.NewClientBuilder().WithObjects(testNamespace).Build()

			r := rules.Rule2000{Client: client}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
				{
					Status:  "Warning",
					Message: "Ingress traffic is not denied by default.",
					Target:  rule.NewTarget("namespace", "test", "details", "namespace is marked for deletion without any present pods"),
				},
				{
					Status:  "Warning",
					Message: "Egress traffic is not denied by default.",
					Target:  rule.NewTarget("namespace", "test", "details", "namespace is marked for deletion without any present pods"),
				},
			}))
		})

		It("should handle accepted namespaces based on options", func() {
			acceptedNamespace := namespaceWithDeletionTimestamp.DeepCopy()
			acceptedNamespace.Name = "accepted-namespace"
			acceptedNamespace.Labels = map[string]string{
				"environment": "production",
			}

			partiallyAcceptedNamespaceWithPod := namespaceWithDeletionTimestamp.DeepCopy()
			partiallyAcceptedNamespaceWithPod.Name = "partially-accepted-with-pod"
			partiallyAcceptedNamespaceWithPod.Labels = map[string]string{
				"team": "security",
			}

			partiallyAcceptedNamespace := namespaceWithDeletionTimestamp.DeepCopy()
			partiallyAcceptedNamespace.Name = "partially-accepted"
			partiallyAcceptedNamespace.Labels = map[string]string{
				"team": "security",
			}

			pod1 := plainPod.DeepCopy()
			pod1.Namespace = "partially-accepted-with-pod"

			client = fakeclient.NewClientBuilder().WithObjects(acceptedNamespace, partiallyAcceptedNamespace, partiallyAcceptedNamespaceWithPod, pod1).Build()

			allowAllPolicy1 := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "allow-all",
					Namespace: "accepted-namespace",
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
			Expect(client.Create(ctx, allowAllPolicy1)).To(Succeed())

			allowAllPolicy2 := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "not-deny",
					Namespace: "partially-accepted",
				},
				Spec: networkingv1.NetworkPolicySpec{
					PolicyTypes: []networkingv1.PolicyType{
						networkingv1.PolicyTypeEgress,
					},
					Egress: []networkingv1.NetworkPolicyEgressRule{{}},
				},
			}
			Expect(client.Create(ctx, allowAllPolicy2)).To(Succeed())

			ruleOptions := &rules.Options2000{
				AcceptedNamespaces: []rules.AcceptedNamespaces2000{
					{
						AcceptedClusterObject: option.AcceptedClusterObject{
							ClusterObjectSelector: option.ClusterObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"environment": "production",
									},
								},
							},
							Justification: "justification 1",
						},
						AcceptedTraffic: rules.AcceptedTraffic{
							Ingress: true,
							Egress:  true,
						},
					},
					{
						AcceptedClusterObject: option.AcceptedClusterObject{
							ClusterObjectSelector: option.ClusterObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"team": "security",
									},
								},
							},
							Justification: "justification 2",
						},
						AcceptedTraffic: rules.AcceptedTraffic{
							Ingress: false,
							Egress:  true,
						},
					},
				},
			}

			r := &rules.Rule2000{Client: client, Options: ruleOptions}
			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(ConsistOf([]rule.CheckResult{
				{
					Status:  rule.Accepted,
					Message: "justification 1",
					Target:  rule.NewTarget("namespace", "accepted-namespace", "details", "traffic: ingress"),
				},
				{
					Status:  rule.Accepted,
					Message: "justification 1",
					Target:  rule.NewTarget("namespace", "accepted-namespace", "details", "traffic: egress"),
				},
				{
					Status:  rule.Failed,
					Message: "Ingress traffic is not denied by default.",
					Target:  rule.NewTarget("namespace", "partially-accepted-with-pod", "details", "namespace is marked for deletion with present pods"),
				},
				{
					Status:  rule.Accepted,
					Message: "justification 2",
					Target:  rule.NewTarget("namespace", "partially-accepted-with-pod", "details", "traffic: egress"),
				},
				{
					Status:  rule.Warning,
					Message: "Ingress traffic is not denied by default.",
					Target:  rule.NewTarget("namespace", "partially-accepted", "details", "namespace is marked for deletion without any present pods"),
				},
				{
					Status:  rule.Accepted,
					Message: "justification 2",
					Target:  rule.NewTarget("namespace", "partially-accepted", "details", "traffic: egress"),
				},
			}))
		})
	})
})
