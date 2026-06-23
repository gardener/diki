// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var _ = Describe("#2007", func() {
	var (
		client        client.Client
		role          *rbacv1.Role
		clusterRole   *rbacv1.ClusterRole
		options       *rules.Options2007
		ctx           = context.TODO()
		namespaceName = "foo"
		namespace     *corev1.Namespace
	)

	BeforeEach(func() {
		client = fakeclient.NewClientBuilder().Build()
		namespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
		}
		role = &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: namespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			Rules: []rbacv1.PolicyRule{},
		}
		clusterRole = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "bar",
				Labels: map[string]string{
					"bar": "foo",
				},
			},
			Rules: []rbacv1.PolicyRule{},
		}
	})

	It("should pass when no roles or clusterRoles are present", func() {
		r := &rules.Rule2007{Client: client}
		ruleResult, err := r.Run(ctx)
		Expect(err).To((BeNil()))
		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{{Status: rule.Passed, Message: "The cluster does not have any Roles or ClusterRoles.", Target: rule.NewTarget()}}))
	})

	It("should pass when all policyRule verbs do not contain *", func() {
		r := &rules.Rule2007{Client: client}

		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			Verbs: []string{"get", "watch"},
		})
		Expect(client.Create(ctx, role)).To(Succeed())

		clusterRole.Rules = append(clusterRole.Rules, rbacv1.PolicyRule{
			Verbs: []string{"update"},
		})
		Expect(client.Create(ctx, clusterRole)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Role does not use \"*\" in policy rule verbs.",
				Target:  rule.NewTarget("kind", "Role", "name", "foo", "namespace", "foo"),
			},
			{
				Status:  rule.Passed,
				Message: "Role does not use \"*\" in policy rule verbs.",
				Target:  rule.NewTarget("kind", "ClusterRole", "name", "bar"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should fail when policyRule verbs contain *", func() {
		r := &rules.Rule2007{Client: client}

		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			Verbs: []string{"get", "*"},
		})
		Expect(client.Create(ctx, role)).To(Succeed())

		clusterRole.Rules = append(clusterRole.Rules, rbacv1.PolicyRule{
			Verbs: []string{"update"},
		}, rbacv1.PolicyRule{
			Verbs: []string{"patch*"},
		})
		Expect(client.Create(ctx, clusterRole)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Failed,
				Message: "Role uses \"*\" in policy rule verbs.",
				Target:  rule.NewTarget("kind", "Role", "name", "foo", "namespace", "foo"),
			},
			{
				Status:  rule.Failed,
				Message: "Role uses \"*\" in policy rule verbs.",
				Target:  rule.NewTarget("kind", "ClusterRole", "name", "bar"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct checkResults when some verbs contain *", func() {
		r := &rules.Rule2007{Client: client}

		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			Verbs: []string{"get", "watch"},
		})
		Expect(client.Create(ctx, role)).To(Succeed())

		clusterRole.Rules = append(clusterRole.Rules, rbacv1.PolicyRule{
			Verbs: []string{"update"},
		}, rbacv1.PolicyRule{
			Verbs: []string{"*"},
		})
		Expect(client.Create(ctx, clusterRole)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Role does not use \"*\" in policy rule verbs.",
				Target:  rule.NewTarget("kind", "Role", "name", "foo", "namespace", "foo"),
			},
			{
				Status:  rule.Failed,
				Message: "Role uses \"*\" in policy rule verbs.",
				Target:  rule.NewTarget("kind", "ClusterRole", "name", "bar"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when options are used", func() {
		options = &rules.Options2007{
			AcceptedRoles: []option.AcceptedNamespacedObject{
				{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
						NamespaceLabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
					},
				},
			},
			AcceptedClusterRoles: []option.AcceptedClusterObject{
				{
					ClusterObjectSelector: option.ClusterObjectSelector{
						MatchLabels: map[string]string{
							"bar": "foo",
						},
					},
					Justification: "justification foo",
				},
			},
		}
		r := &rules.Rule2007{Client: client, Options: options}
		Expect(client.Create(ctx, namespace)).To(Succeed())

		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			Verbs: []string{"get", "*"},
		})
		Expect(client.Create(ctx, role)).To(Succeed())

		clusterRole.Rules = append(clusterRole.Rules, rbacv1.PolicyRule{
			Verbs: []string{"update"},
		}, rbacv1.PolicyRule{
			Verbs: []string{"patch*"},
		})
		Expect(client.Create(ctx, clusterRole)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Accepted,
				Message: "Role is accepted to use \"*\" in policy rule verbs.",
				Target:  rule.NewTarget("kind", "Role", "name", "foo", "namespace", "foo"),
			},
			{
				Status:  rule.Accepted,
				Message: "justification foo",
				Target:  rule.NewTarget("kind", "ClusterRole", "name", "bar"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	Describe("#Merge Options2007", func() {
		It("should merge two Options2007 by appending both slices", func() {
			base := &rules.Options2007{
				AcceptedRoles: []option.AcceptedNamespacedObject{
					{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							LabelSelector:          &metav1.LabelSelector{MatchLabels: map[string]string{"role": "base"}},
							NamespaceLabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"ns": "base"}},
						},
						Justification: "base role",
					},
				},
				AcceptedClusterRoles: []option.AcceptedClusterObject{
					{
						ClusterObjectSelector: option.ClusterObjectSelector{
							LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"cr": "base"}},
						},
						Justification: "base cluster role",
					},
				},
			}

			override := &rules.Options2007{
				AcceptedRoles: []option.AcceptedNamespacedObject{
					{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							LabelSelector:          &metav1.LabelSelector{MatchLabels: map[string]string{"role": "override"}},
							NamespaceLabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"ns": "override"}},
						},
						Justification: "override role",
					},
				},
				AcceptedClusterRoles: []option.AcceptedClusterObject{
					{
						ClusterObjectSelector: option.ClusterObjectSelector{
							LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"cr": "override"}},
						},
						Justification: "override cluster role",
					},
				},
			}

			merged, err := base.Merge(override)
			Expect(err).ToNot(HaveOccurred())

			mergedOpts, ok := merged.(*rules.Options2007)
			Expect(ok).To(BeTrue())
			Expect(mergedOpts.AcceptedRoles).To(HaveLen(2))
			Expect(mergedOpts.AcceptedRoles[0].Justification).To(Equal("base role"))
			Expect(mergedOpts.AcceptedRoles[1].Justification).To(Equal("override role"))
			Expect(mergedOpts.AcceptedClusterRoles).To(HaveLen(2))
			Expect(mergedOpts.AcceptedClusterRoles[0].Justification).To(Equal("base cluster role"))
			Expect(mergedOpts.AcceptedClusterRoles[1].Justification).To(Equal("override cluster role"))
		})

		It("should return the receiver when merging with nil", func() {
			base := &rules.Options2007{
				AcceptedRoles: []option.AcceptedNamespacedObject{
					{Justification: "base"},
				},
			}

			merged, err := base.Merge(nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(merged).To(Equal(base))
		})

		It("should handle merging two empty Options2007", func() {
			base := &rules.Options2007{}
			other := &rules.Options2007{}

			merged, err := base.Merge(other)
			Expect(err).ToNot(HaveOccurred())

			mergedOpts, ok := merged.(*rules.Options2007)
			Expect(ok).To(BeTrue())
			Expect(mergedOpts.AcceptedRoles).To(BeEmpty())
			Expect(mergedOpts.AcceptedClusterRoles).To(BeEmpty())
		})

		It("should return an error when merging with a different option type", func() {
			base := &rules.Options2007{}
			other := &rules.Options2000{}

			merged, err := base.Merge(other)
			Expect(err).To(MatchError(ContainSubstring("cannot merge options of type")))
			Expect(merged).To(BeNil())
		})
	})
})
