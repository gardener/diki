// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/garden/ruleset/securityhardenedshoot/rules"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#2006", func() {
	var (
		fakeClient     client.Client
		ctx            = context.TODO()
		shootName      = "foo"
		shootNamespace = "bar"

		shoot *gardencorev1beta1.Shoot

		r        rule.Rule
		ruleName = "Shoot clusters must have static token kubeconfig disabled."
		ruleID   = "2006"
		severity = rule.SeverityHigh
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.GardenScheme).Build()
		shoot = &gardencorev1beta1.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      shootName,
				Namespace: shootNamespace,
			},
		}
		r = &rules.Rule2006{
			Client:         fakeClient,
			ShootName:      shootName,
			ShootNamespace: shootNamespace,
		}
	})

	DescribeTable("Run cases", func(updateFn func(), expectedCheckResult rule.CheckResult) {
		updateFn()
		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())
		res, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(Equal(rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: severity, CheckResults: []rule.CheckResult{expectedCheckResult}}))
	},
		Entry("should error when the shoot can't be found",
			func() { shoot.Name = "notFoo" },
			rule.CheckResult{Status: rule.Errored, Message: "shoots.core.gardener.cloud \"foo\" not found", Target: rule.NewTarget("name", "foo", "namespace", "bar", "kind", "Shoot")},
		),
		Entry("should error if the kubernetes version is not specified",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{}
			},
			rule.CheckResult{Status: rule.Errored, Message: "Invalid Semantic Version", Target: rule.NewTarget()},
		),
		Entry("should pass when the kubernetes version is above 1.26",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					Version: "1.27.0",
				}
			},
			rule.CheckResult{Status: rule.Passed, Message: "Static token kubeconfig is locked to disabled for the shoot (Kubernetes version >= 1.27).", Target: rule.NewTarget()},
		),
		Entry("should pass when Static token kubeconfig is default",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					Version: "1.26.0",
				}
			},
			rule.CheckResult{Status: rule.Passed, Message: "Static token kubeconfig is disabled for the shoot by default.", Target: rule.NewTarget()},
		),
		Entry("should pass when Static token kubeconfig is disabled",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					Version:                     "1.26.0",
					EnableStaticTokenKubeconfig: ptr.To(false),
				}
			},
			rule.CheckResult{Status: rule.Passed, Message: "Static token kubeconfig is disabled for the shoot.", Target: rule.NewTarget()},
		),
		Entry("should fail when Static token kubeconfig is enabled",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					Version:                     "1.26.0",
					EnableStaticTokenKubeconfig: ptr.To(true),
				}
			},
			rule.CheckResult{Status: rule.Failed, Message: "Static token kubeconfig is enabled for the shoot.", Target: rule.NewTarget()},
		),
	)
})
