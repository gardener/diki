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

var _ = Describe("#2006", func() {
	var (
		client        client.Client
		role          *rbacv1.Role
		clusterRole   *rbacv1.ClusterRole
		options       *rules.Options2006
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
		r := &rules.Rule2006{Client: client}
		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{{Status: rule.Passed, Message: "The cluster does not have any Roles or ClusterRoles.", Target: rule.NewTarget()}}))
	})

	It("should pass when all policyRule resources do not contain *", func() {
		r := &rules.Rule2006{Client: client}

		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			Resources: []string{"pods", "secret"},
		})
		Expect(client.Create(ctx, role)).To(Succeed())

		clusterRole.Rules = append(clusterRole.Rules, rbacv1.PolicyRule{
			Resources: []string{"configmaps"},
		})
		Expect(client.Create(ctx, clusterRole)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Role does not use \"*\" in policy rule resources.",
				Target:  rule.NewTarget("kind", "role", "name", "foo", "namespace", "foo"),
			},
			{
				Status:  rule.Passed,
				Message: "Role does not use \"*\" in policy rule resources.",
				Target:  rule.NewTarget("kind", "clusterRole", "name", "bar"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should fail when policyRule resources contain *", func() {
		r := &rules.Rule2006{Client: client}

		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			Resources: []string{"pods", "*"},
		})
		Expect(client.Create(ctx, role)).To(Succeed())

		clusterRole.Rules = append(clusterRole.Rules, rbacv1.PolicyRule{
			Resources: []string{"configmaps"},
		}, rbacv1.PolicyRule{
			Resources: []string{"config*"},
		})
		Expect(client.Create(ctx, clusterRole)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Failed,
				Message: "Role uses \"*\" in policy rule resources.",
				Target:  rule.NewTarget("kind", "role", "name", "foo", "namespace", "foo"),
			},
			{
				Status:  rule.Failed,
				Message: "Role uses \"*\" in policy rule resources.",
				Target:  rule.NewTarget("kind", "clusterRole", "name", "bar"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct checkResults when some resources contain *", func() {
		r := &rules.Rule2006{Client: client}

		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			Resources: []string{"pods", "secrets"},
		})
		Expect(client.Create(ctx, role)).To(Succeed())

		clusterRole.Rules = append(clusterRole.Rules, rbacv1.PolicyRule{
			Resources: []string{"configmaps"},
		}, rbacv1.PolicyRule{
			Resources: []string{"*"},
		})
		Expect(client.Create(ctx, clusterRole)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Role does not use \"*\" in policy rule resources.",
				Target:  rule.NewTarget("kind", "role", "name", "foo", "namespace", "foo"),
			},
			{
				Status:  rule.Failed,
				Message: "Role uses \"*\" in policy rule resources.",
				Target:  rule.NewTarget("kind", "clusterRole", "name", "bar"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when options are used", func() {
		options = &rules.Options2006{
			AcceptedRoles: []option.AcceptedNamespacedObject{
				{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						MatchLabels: map[string]string{
							"foo": "bar",
						},
						NamespaceMatchLabels: map[string]string{
							"foo": "bar",
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
		r := &rules.Rule2006{Client: client, Options: options}
		Expect(client.Create(ctx, namespace)).To(Succeed())

		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			Resources: []string{"pods", "*"},
		})
		Expect(client.Create(ctx, role)).To(Succeed())

		clusterRole.Rules = append(clusterRole.Rules, rbacv1.PolicyRule{
			Resources: []string{"configmaps"},
		}, rbacv1.PolicyRule{
			Resources: []string{"config*"},
		})
		Expect(client.Create(ctx, clusterRole)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Accepted,
				Message: "Role is accepted to use \"*\" in policy rule resources.",
				Target:  rule.NewTarget("kind", "role", "name", "foo", "namespace", "foo"),
			},
			{
				Status:  rule.Accepted,
				Message: "justification foo",
				Target:  rule.NewTarget("kind", "clusterRole", "name", "bar"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
})
