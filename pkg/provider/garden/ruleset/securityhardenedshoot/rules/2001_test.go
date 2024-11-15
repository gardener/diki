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

var _ = Describe("#2001", func() {
	var (
		fakeClient    client.Client
		ctx           = context.TODO()
		shootName     = "foo"
		namespaceName = "bar"

		shoot    *gardencorev1beta1.Shoot
		r        rule.Rule
		ruleName = "Shoot clusters must disable ssh access to worker nodes."
		ruleID   = "2001"
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.GardenScheme).Build()
		shoot = &gardencorev1beta1.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      shootName,
				Namespace: namespaceName,
			},
		}
		r = &rules.Rule2001{
			ShootName:      shootName,
			ShootNamespace: namespaceName,
			Client:         fakeClient,
		}
	})

	DescribeTable("Run cases",
		func(updateFn func(), expectedResults []rule.CheckResult) {
			updateFn()

			Expect(fakeClient.Create(ctx, shoot)).To(Succeed())
			res, err := r.Run(ctx)
			Expect(err).To(BeNil())
			Expect(res).To(Equal(rule.RuleResult{RuleID: ruleID, RuleName: ruleName, CheckResults: expectedResults, Severity: rule.SeverityMedium}))
		},

		Entry("should error when the shoot is not found",
			func() { shoot.Name = "notFoo" },
			rule.CheckResult{Status: rule.Errored, Message: "shoots.core.gardener.cloud \"foo\" not found", Target: rule.NewTarget("kind", "Shoot", "name", "foo", "namespace", "bar")},
		),
		Entry("should fail when the WorkersSettings field is not specified",
			func() { shoot.Spec.Provider = gardencorev1beta1.Provider{} },
			rule.CheckResult{Status: rule.Failed, Message: "SSH access is not disabled for worker nodes.", Target: rule.NewTarget()},
		),
		Entry("should fail when the SSHAccess field is not specified",
			func() { shoot.Spec.Provider.WorkersSettings = &gardencorev1beta1.WorkersSettings{} },
			rule.CheckResult{Status: rule.Failed, Message: "SSH access is not disabled for worker nodes.", Target: rule.NewTarget()},
		),
		Entry("should fail when the SSH access is enabled",
			func() {
				shoot.Spec.Provider.WorkersSettings = ptr.To(gardencorev1beta1.WorkersSettings{SSHAccess: ptr.To(gardencorev1beta1.SSHAccess{Enabled: true})})
			},
			rule.CheckResult{Status: rule.Failed, Message: "SSH access is enabled for worker nodes.", Target: rule.NewTarget()},
		),
		Entry("should pass when the SSH access is disabled",
			func() {
				shoot.Spec.Provider.WorkersSettings = ptr.To(gardencorev1beta1.WorkersSettings{SSHAccess: ptr.To(gardencorev1beta1.SSHAccess{Enabled: false})})
			},
			rule.CheckResult{Status: rule.Passed, Message: "SSH access is disabled for worker nodes.", Target: rule.NewTarget()},
		),
	)
})
