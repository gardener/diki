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

var _ = Describe("#2000", func() {
	var (
		fakeClient     client.Client
		ctx            = context.TODO()
		shootName      = "foo"
		shootNamespace = "bar"

		shoot    *gardencorev1beta1.Shoot
		r        rule.Rule
		ruleName = "Shoot clusters must have anonymous authentication disabled for the Kubernetes API server."
		ruleID   = "2000"
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

		r = &rules.Rule2000{
			Client:         fakeClient,
			ShootName:      shootName,
			ShootNamespace: shootNamespace,
		}
	})

	DescribeTable("Run cases", func(updateFn func(), expectedCheckResults []rule.CheckResult) {
		updateFn()
		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())
		res, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(Equal(rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: severity, CheckResults: expectedCheckResults}))
	},
		Entry("should error when the shoot is not found",
			func() { shoot.Name = "notFoo" },
			[]rule.CheckResult{{Status: rule.Errored, Message: "shoots.core.gardener.cloud \"foo\" not found", Target: rule.NewTarget("kind", "Shoot", "name", "foo", "namespace", "bar")}},
		),
		Entry("should pass when kube-apiserver configuration is not set",
			func() {},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Anonymous authentication is not enabled.", Target: rule.NewTarget()}},
		),
		Entry("should pass when anonymous authentication is not set",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						KubernetesConfig: gardencorev1beta1.KubernetesConfig{
							FeatureGates: map[string]bool{"foo": true},
						},
					},
				}
			},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Anonymous authentication is not enabled.", Target: rule.NewTarget()}},
		),
		Entry("should pass when anonymous authentication is disabled",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						EnableAnonymousAuthentication: ptr.To(false),
					},
				}
			},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Anonymous authentication is disabled on the kube-apiserver.", Target: rule.NewTarget()}},
		),
		Entry("should fail when anonymous authentication is enabled",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						EnableAnonymousAuthentication: ptr.To(true),
					},
				}
			},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Anonymous authentication is enabled on the kube-apiserver.", Target: rule.NewTarget()}},
		),
	)
})
