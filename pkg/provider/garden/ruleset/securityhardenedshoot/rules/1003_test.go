// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"
	"encoding/json"

	lakomapi "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
	lakomv1alpha1 "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom/v1alpha1"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
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

		kubeSystemManagedByGardenerScope lakomapi.ScopeType = "KubeSystemManagedByGardener"
		kubeSystemScope                  lakomapi.ScopeType = "KubeSystem"
		clusterScope                     lakomapi.ScopeType = "Cluster"
		fakeScope                        lakomapi.ScopeType = "Fake"

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

	DescribeTable("Run cases", func(updateFn func(), options *rules.Options1003, expectedCheckResults []rule.CheckResult) {
		updateFn()

		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())

		r = &rules.Rule1003{
			Client:         fakeClient,
			ShootName:      shootName,
			ShootNamespace: shootNamespace,
			Options:        options,
		}

		res, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(Equal(rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: severity, CheckResults: expectedCheckResults}))
	},
		Entry("should error when the shoot can't be found",
			func() { shoot.Name = "notFoo" },
			nil,
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
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Extension shoot-lakom-service is not configured for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
		Entry("should pass when Lakom extension does not have extension config",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/shoot-lakom-service": "true",
				}
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Extension shoot-lakom-service configured correctly for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when Lakom extension does not have extension config and default scope is not allowed",
			func() {
				shoot.Labels = map[string]string{
					"extensions.extensions.gardener.cloud/shoot-lakom-service": "true",
				}
			},
			&rules.Options1003{
				AllowedLakomScopes: []lakomapi.ScopeType{kubeSystemScope, clusterScope},
			},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Extension shoot-lakom-service is not configured with allowed scope.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when Lakom extension is explicitly disabled but label is missing",
			func() {
				shoot.Spec.Extensions = []gardencorev1beta1.Extension{
					{
						Type:     "shoot-lakom-service",
						Disabled: ptr.To(true),
					},
				}
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Extension shoot-lakom-service is not configured for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
		Entry("should warn when Lakom extension is explicitly disabled but label says extension is enabled",
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
			nil,
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
			nil,
			[]rule.CheckResult{
				{Status: rule.Warning, Message: "Extension shoot-lakom-service has unexpected label value: false.", Target: rule.NewTarget()},
			},
		),
		Entry("should pass when Lakom extension does not have provider config",
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
			nil,
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Extension shoot-lakom-service configured correctly for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when Lakom extension does not have provider config and default scope is not allowed",
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
			&rules.Options1003{
				AllowedLakomScopes: []lakomapi.ScopeType{kubeSystemScope, clusterScope},
			},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Extension shoot-lakom-service is not configured with allowed scope.", Target: rule.NewTarget()},
			},
		),
		Entry("should pass when Lakom extension is configured",
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
			nil,
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Extension shoot-lakom-service configured correctly for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when Lakom does not use allowed scope",
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
								Scope: &kubeSystemScope,
							}),
						},
					},
				}
			},
			&rules.Options1003{
				AllowedLakomScopes: []lakomapi.ScopeType{clusterScope},
			},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Extension shoot-lakom-service is not configured with allowed scope.", Target: rule.NewTarget()},
			},
		),
		Entry("should pass when Lakom extension uses allowed scope",
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
								Scope: &clusterScope,
							}),
						},
					},
				}
			},
			&rules.Options1003{
				AllowedLakomScopes: []lakomapi.ScopeType{clusterScope},
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Extension shoot-lakom-service configured correctly for the shoot cluster.", Target: rule.NewTarget()},
			},
		),
	)
	Describe("#ValidateOptions", func() {
		It("should not error when options are correct", func() {
			options := rules.Options1003{
				AllowedLakomScopes: []lakomapi.ScopeType{kubeSystemManagedByGardenerScope, kubeSystemScope, clusterScope},
			}

			result := options.Validate(field.NewPath("foo"))
			Expect(result).To(BeEmpty())
		})
		It("should error when options are incorrect", func() {
			options := rules.Options1003{
				AllowedLakomScopes: []lakomapi.ScopeType{kubeSystemScope, fakeScope, clusterScope},
			}
			result := options.Validate(field.NewPath("foo"))
			Expect(result).To(Equal(field.ErrorList{
				{
					Type:     field.ErrorTypeInvalid,
					Field:    "foo.allowedLakomScopes[1]",
					BadValue: fakeScope,
					Detail:   "must be valid Lakom Scope",
				},
			}))
		})
	})
})
