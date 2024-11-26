// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s/rules"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#2006", func() {
	var (
		client        client.Client
		role          *rbacv1.Role
		clusterRole   *rbacv1.ClusterRole
		ctx           = context.TODO()
		namespaceName = "foo"
	)

	BeforeEach(func() {
		client = fakeclient.NewClientBuilder().Build()
		role = &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: namespaceName,
			},
			Rules: []rbacv1.PolicyRule{},
		}
		clusterRole = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "bar",
			},
			Rules: []rbacv1.PolicyRule{},
		}
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
				Message: "Did not find \"*\" in policyRule resources.",
				Target:  rule.NewTarget("kind", "role", "name", "foo", "namespace", "foo"),
			},
			{
				Status:  rule.Passed,
				Message: "Did not find \"*\" in policyRule resources.",
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
				Message: "Found \"*\" in policyRule resources.",
				Target:  rule.NewTarget("kind", "role", "name", "foo", "namespace", "foo"),
			},
			{
				Status:  rule.Failed,
				Message: "Found \"*\" in policyRule resources.",
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
				Message: "Did not find \"*\" in policyRule resources.",
				Target:  rule.NewTarget("kind", "role", "name", "foo", "namespace", "foo"),
			},
			{
				Status:  rule.Failed,
				Message: "Found \"*\" in policyRule resources.",
				Target:  rule.NewTarget("kind", "clusterRole", "name", "bar"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
})
