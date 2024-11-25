// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	"github.com/gardener/diki/pkg/provider/garden/ruleset/securityhardenedshoot/rules"
	"github.com/gardener/diki/pkg/rule"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("#1000", func() {
	var (
		fakeClient = client.Client
		ctx        = context.TODO()

		shoot *gardencorev1beta.Shoot

		shootName      = "foo"
		shootNamespace = "bar"

		r        rule.Rule
		ruleID   = "1000"
		ruleName = "Shoot clusters should enable required extensions. This rule can be configured as per organisation's requirements in order to check if required extensions are enabled for the shoot cluster."
		severity = rule.SeverityHigh
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.GardenScheme).Build()
		shoot = &gardencorev1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Name: shootName, Namespace: shootNamespace}}
	})

	DescribeTable("Run cases", func(updateFn func(), options *rules.Options1000, expectedCheckResults []rule.CheckResult) {
		updateFn()

		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())

		r = &rules.Rule1000{
			Client:         fakeClient,
			ShootName:      shootName,
			ShootNamespace: shootNamespace,
			Options:        options,
		}

		res, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(Equal(rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: severity, CheckResults: expectedCheckResults}))
	},
		Entry())
})
