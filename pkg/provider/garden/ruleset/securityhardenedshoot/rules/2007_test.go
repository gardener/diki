// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"
	"encoding/json"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	admissionapiv1 "k8s.io/pod-security-admission/admission/api/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	intkubeutils "github.com/gardener/diki/pkg/internal/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/garden/ruleset/securityhardenedshoot/rules"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#2007", func() {
	var (
		fakeClient client.Client
		ctx        = context.TODO()
		shoot      *gardencorev1beta1.Shoot

		shootName      = "foo"
		shootNamespace = "bar"

		r               rule.Rule
		ruleID          = "2007"
		ruleName        = "Shoot clusters must have a PodSecurity admission plugin configured."
		severity        = rule.SeverityHigh
		podSecurity     = "PodSecurity"
		standardOptions = rules.Options2007{MinPodSecurityStandardsProfile: "baseline"}
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.GardenScheme).Build()
		shoot = &gardencorev1beta1.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      shootName,
				Namespace: shootNamespace,
			},
		}
	})

	DescribeTable("Run cases", func(updateFn func(), options *rules.Options2007, expectedResult []rule.CheckResult) {
		updateFn()

		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())

		r = &rules.Rule2007{Client: fakeClient, ShootName: shootName, ShootNamespace: shootNamespace, Options: options}
		res, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(Equal(rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: severity, CheckResults: expectedResult}))
	},
		Entry("should error when the shoot can't be found",
			func() { shoot.Name = "notFoo" },
			&rules.Options2007{
				MinPodSecurityStandardsProfile: "baseline",
			},
			[]rule.CheckResult{
				{Status: rule.Errored, Message: "shoots.core.gardener.cloud \"foo\" not found", Target: rule.NewTarget("name", "foo", "namespace", "bar", "kind", "Shoot")},
			},
		),
		Entry("should fail when the kubeapiserver has a default configuration",
			func() {
				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{}
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "PodSecurity admission plugin is not configured.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when the PodSecurity admission plugin is not present",
			func() {
				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name: "foo",
						},
						{
							Name: "bar",
						},
					},
				}
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "PodSecurity admission plugin is not configured.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when the PodSecurity admission plugin is disabled",
			func() {
				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name:     podSecurity,
							Disabled: ptr.To(true),
						},
					},
				}
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "PodSecurity admission plugin is disabled.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when the PodSecurity admission plugin is both enabled and disabled",
			func() {
				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name:     podSecurity,
							Disabled: ptr.To(true),
						},
						{
							Name:     podSecurity,
							Disabled: ptr.To(false),
						},
					},
				}
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "PodSecurity admission plugin is disabled.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when the PodSecurity admission plugin has a default configuration",
			func() {
				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name:     podSecurity,
							Disabled: ptr.To(false),
						},
					},
				}
			},
			&standardOptions,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "PodSecurity admission plugin is not configured.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when the PodSecurity admission plugin's privileges are default",
			func() {
				rawExtensionBytes, err := json.Marshal(&admissionapiv1.PodSecurityConfiguration{
					Defaults: admissionapiv1.PodSecurityDefaults{},
				})
				Expect(err).To(BeNil())

				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name:     podSecurity,
							Disabled: ptr.To(false),
							Config: &runtime.RawExtension{
								Raw: rawExtensionBytes,
							},
						},
					},
				}
			},
			&standardOptions,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Enforce mode profile is less restrictive than the minimum Pod Security Standards profile allowed: baseline.", Target: rule.NewTarget("kind", "PodSecurityConfiguration")},
				{Status: rule.Failed, Message: "Warn mode profile is less restrictive than the minimum Pod Security Standards profile allowed: baseline.", Target: rule.NewTarget("kind", "PodSecurityConfiguration")},
				{Status: rule.Failed, Message: "Audit mode profile is less restrictive than the minimum Pod Security Standards profile allowed: baseline.", Target: rule.NewTarget("kind", "PodSecurityConfiguration")},
			},
		),
		Entry("should pass when PodSecurity admission plugin's restrictions are exceeding the maximal restriction",
			func() {

				rawExtensionBytes, err := json.Marshal(&admissionapiv1.PodSecurityConfiguration{
					Defaults: admissionapiv1.PodSecurityDefaults{
						Enforce: "baseline",
						Audit:   "baseline",
						Warn:    "restricted",
					},
				})
				Expect(err).To(BeNil())

				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name:     podSecurity,
							Disabled: ptr.To(false),
							Config: &runtime.RawExtension{
								Raw: rawExtensionBytes,
							},
						},
					},
				}
			},
			&standardOptions,
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "PodSecurity admission plugin is configured correctly.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail only on PodSecurity defaults that are exceeding the the maximal restriction",
			func() {
				rawExtensionBytes, err := json.Marshal(&admissionapiv1.PodSecurityConfiguration{
					Defaults: admissionapiv1.PodSecurityDefaults{
						Enforce: "baseline",
						Audit:   "privileged",
					},
				})
				Expect(err).To(BeNil())

				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name:     podSecurity,
							Disabled: ptr.To(false),
							Config: &runtime.RawExtension{
								Raw: rawExtensionBytes,
							},
						},
					},
				}
			},
			&standardOptions,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Warn mode profile is less restrictive than the minimum Pod Security Standards profile allowed: baseline.", Target: rule.NewTarget("kind", "PodSecurityConfiguration")},
				{Status: rule.Failed, Message: "Audit mode profile is less restrictive than the minimum Pod Security Standards profile allowed: baseline.", Target: rule.NewTarget("kind", "PodSecurityConfiguration")},
			},
		),
		Entry("should evaluate PodSecurity privileges correctly when the maximal restriction is default",
			func() {
				rawExtensionBytes, err := json.Marshal(&admissionapiv1.PodSecurityConfiguration{
					Defaults: admissionapiv1.PodSecurityDefaults{
						Enforce: "baseline",
						Audit:   "privileged",
						Warn:    "restricted",
					},
				})
				Expect(err).To(BeNil())

				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name:     podSecurity,
							Disabled: ptr.To(false),
							Config: &runtime.RawExtension{
								Raw: rawExtensionBytes,
							},
						},
					},
				}
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Audit mode profile is less restrictive than the minimum Pod Security Standards profile allowed: baseline.", Target: rule.NewTarget("kind", "PodSecurityConfiguration")},
			},
		),
	)

	Describe("#Validate", func() {
		It("should not error when options are correct", func() {
			options := &rules.Options2007{
				MinPodSecurityStandardsProfile: "baseline",
			}

			result := options.Validate(field.NewPath("foo"))

			Expect(result).To(BeNil())
		})
		It("should return correct error when option is misconfigured", func() {
			options := &rules.Options2007{
				MinPodSecurityStandardsProfile: "foo",
			}

			result := options.Validate(field.NewPath("foo"))

			Expect(result).To(Equal(field.ErrorList{
				{
					Type:     field.ErrorTypeInvalid,
					Field:    "foo.minPodSecurityStandardsProfile",
					BadValue: intkubeutils.PodSecurityStandardProfile("foo"),
					Detail:   "must be one of 'restricted', 'baseline' or 'privileged'",
				},
			}))
		})
	})
})
