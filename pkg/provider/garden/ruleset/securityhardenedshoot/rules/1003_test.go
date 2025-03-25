// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"
	"encoding/json"

	lakomv1alpha1 "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom/v1alpha1"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/garden/ruleset/securityhardenedshoot/rules"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#1003", func() {
	var (
		fakeClient client.Client
		ctx        = context.TODO()

		shoot *gardencorev1beta1.Shoot

		shootName      = "foo"
		shootNamespace = "bar"

		r        rule.Rule
		ruleID   = "1003"
		ruleName = "Shoot clusters must have the Lakom extension configured."
		severity = rule.SeverityHigh

		encode = func(obj runtime.Object) []byte {
			data, err := json.Marshal(obj)
			Expect(err).ToNot(HaveOccurred())

			return data
		}
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.GardenScheme).Build()
		shoot = &gardencorev1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Name: shootName, Namespace: shootNamespace}}
	})

	DescribeTable("Run cases", func(updateFn func(), expectedCheckResults []rule.CheckResult) {
		updateFn()

		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())

		r = &rules.Rule1003{
			Client:         fakeClient,
			ShootName:      shootName,
			ShootNamespace: shootNamespace,
		}

		res, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(Equal(rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: severity, CheckResults: expectedCheckResults}))
	},
		Entry("should error when the shoot can't be found",
			func() { shoot.Name = "notFoo" },
			[]rule.CheckResult{
				{Status: rule.Errored, Message: "shoots.core.gardener.cloud \"foo\" not found", Target: rule.NewTarget("name", "foo", "namespace", "bar", "kind", "Shoot")},
			},
		),
		Entry("should fail when Lakom extension is not configured",
			func() {
				shoot.Spec.Extensions = []gardencorev1beta1.Extension{
					{
						Type: "shoot-lakom-service",
					},
				}
			},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Extension shoot-lakom-service is not configured for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when Lakom extension does not have extension configuration",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/shoot-lakom-service": "true",
				}
			},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Extension shoot-lakom-service is not configured for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
		Entry("should warn when Lakom extension is disabled",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/shoot-lakom-service": "true",
				}
				shoot.Spec.Extensions = []gardencorev1beta1.Extension{
					{
						Type:     "shoot-lakom-service",
						Disabled: ptr.To(true),
					},
				}
			},
			[]rule.CheckResult{
				{Status: rule.Warning, Message: "Extension shoot-lakom-service is disabled in the shoot spec and enabled in labels.", Target: rule.NewTarget()},
			},
		),
		Entry("should warn when Lakom extension has unecpected value in the shoot labels",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/shoot-lakom-service": "false",
				}
			},
			[]rule.CheckResult{
				{Status: rule.Warning, Message: "Extension shoot-lakom-service has unexpected label value: false.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when Lakom extension does not have provider config",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/shoot-lakom-service": "true",
				}
				shoot.Spec.Extensions = []gardencorev1beta1.Extension{
					{
						Type: "shoot-lakom-service",
					},
				}
			},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Extension shoot-lakom-service is not configured for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when Lakom extension does not have trustedKeysResourceName set",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/shoot-lakom-service": "true",
				}
				shoot.Spec.Extensions = []gardencorev1beta1.Extension{
					{
						Type: "shoot-lakom-service",
						ProviderConfig: &runtime.RawExtension{
							Raw: encode(&lakomv1alpha1.LakomConfig{
								TypeMeta: metav1.TypeMeta{
									APIVersion: lakomv1alpha1.SchemeGroupVersion.String(),
									Kind:       "LakomConfig",
								},
							}),
						},
					},
				}
			},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Extension shoot-lakom-service does not configure trusted keys.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when Lakom extension has trustedKeysResourceName set to empty string",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/shoot-lakom-service": "true",
				}
				shoot.Spec.Extensions = []gardencorev1beta1.Extension{
					{
						Type: "shoot-lakom-service",
						ProviderConfig: &runtime.RawExtension{
							Raw: encode(&lakomv1alpha1.LakomConfig{
								TypeMeta: metav1.TypeMeta{
									APIVersion: lakomv1alpha1.SchemeGroupVersion.String(),
									Kind:       "LakomConfig",
								},
								TrustedKeysResourceName: ptr.To(""),
							}),
						},
					},
				}
			},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Extension shoot-lakom-service does not configure trusted keys.", Target: rule.NewTarget()},
			},
		),
		Entry("should pass when Lakom extension has trustedKeysResourceName set",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/shoot-lakom-service": "true",
				}
				shoot.Spec.Extensions = []gardencorev1beta1.Extension{
					{
						Type: "shoot-lakom-service",
						ProviderConfig: &runtime.RawExtension{
							Raw: encode(&lakomv1alpha1.LakomConfig{
								TypeMeta: metav1.TypeMeta{
									APIVersion: lakomv1alpha1.SchemeGroupVersion.String(),
									Kind:       "LakomConfig",
								},
								TrustedKeysResourceName: ptr.To("foo"),
							}),
						},
					},
				}
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Extension shoot-lakom-service configures trusted keys.", Target: rule.NewTarget()},
			},
		),
	)
})
