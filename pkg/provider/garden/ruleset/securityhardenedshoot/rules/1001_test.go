// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
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
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/garden/ruleset/securityhardenedshoot/rules"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#1001", func() {
	var (
		fakeClient         client.Client
		ctx                = context.TODO()
		shootName          = "foo"
		shootNamespace     = "bar"
		cloudProfileName   = "foo"
		nsCloudProfileName = "foo"

		deprecatedClassification                                         = gardencorev1beta1.ClassificationDeprecated
		supportedClassification                                          = gardencorev1beta1.ClassificationSupported
		previewClassification                                            = gardencorev1beta1.ClassificationPreview
		fakeClassification       gardencorev1beta1.VersionClassification = "fake"

		shoot          *gardencorev1beta1.Shoot
		cloudProfile   *gardencorev1beta1.CloudProfile
		nsCloudProfile *gardencorev1beta1.NamespacedCloudProfile
		r              rule.Rule
		ruleName       = "Shoot clusters should use a supported version of Kubernetes."
		ruleID         = "1001"
		severity       = rule.SeverityHigh
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.GardenScheme).Build()

		shoot = &gardencorev1beta1.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      shootName,
				Namespace: shootNamespace,
			},
		}

		cloudProfile = &gardencorev1beta1.CloudProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name: cloudProfileName,
			},
			Spec: gardencorev1beta1.CloudProfileSpec{
				Kubernetes: gardencorev1beta1.KubernetesSettings{
					Versions: []gardencorev1beta1.ExpirableVersion{
						{
							Version:        "1",
							Classification: &supportedClassification,
						},
						{
							Version:        "2",
							Classification: &deprecatedClassification,
						},
						{
							Version:        "3",
							Classification: &previewClassification,
						},
					},
				},
			},
		}

		Expect(fakeClient.Create(ctx, cloudProfile)).To(Succeed())

		nsCloudProfile = &gardencorev1beta1.NamespacedCloudProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nsCloudProfileName,
				Namespace: shootNamespace,
			},
			Spec: gardencorev1beta1.NamespacedCloudProfileSpec{
				Kubernetes: &gardencorev1beta1.KubernetesSettings{
					Versions: []gardencorev1beta1.ExpirableVersion{
						{
							Version:        "4",
							Classification: &supportedClassification,
						},
					},
				},
			},
			Status: gardencorev1beta1.NamespacedCloudProfileStatus{
				CloudProfileSpec: gardencorev1beta1.CloudProfileSpec{
					Kubernetes: gardencorev1beta1.KubernetesSettings{
						Versions: []gardencorev1beta1.ExpirableVersion{
							{
								Version:        "2",
								Classification: &supportedClassification,
							},
							{
								Version:        "3",
								Classification: &previewClassification,
							},
							{
								Version:        "5",
								Classification: &deprecatedClassification,
							},
							{
								Version: "6",
							},
						},
					},
				},
			},
		}

		Expect(fakeClient.Create(ctx, nsCloudProfile)).To(Succeed())
	})

	DescribeTable("Run cases", func(updateFn func(), options *rules.Options1001, expectedCheckResults []rule.CheckResult) {
		updateFn()
		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())

		r = &rules.Rule1001{
			Client:         fakeClient,
			ShootName:      shootName,
			ShootNamespace: shootNamespace,
			Options:        options,
		}

		res, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(Equal(rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: severity, CheckResults: expectedCheckResults}))
	},
		Entry("should error when the shoot is not found",
			func() { shoot.Name = "notFoo" },
			nil,
			[]rule.CheckResult{
				{Status: rule.Errored, Message: "shoots.core.gardener.cloud \"foo\" not found", Target: rule.NewTarget("kind", "Shoot", "name", "foo", "namespace", "bar")},
			},
		),
		Entry("should error when the specified cloudProfile is not found",
			func() { shoot.Spec.CloudProfileName = ptr.To("notFoo") },
			nil,
			[]rule.CheckResult{
				{Status: rule.Errored, Message: "cloudprofiles.core.gardener.cloud \"notFoo\" not found", Target: rule.NewTarget("kind", "CloudProfile", "name", "notFoo")},
			},
		),
		Entry("should error when the specified namespacedCloudProfile is not found",
			func() {
				shoot.Spec.CloudProfile = &gardencorev1beta1.CloudProfileReference{
					Name: "notFoo",
					Kind: "NamespacedCloudProfile",
				}
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Errored, Message: "namespacedcloudprofiles.core.gardener.cloud \"notFoo\" not found", Target: rule.NewTarget("kind", "NamespacedCloudProfile", "name", "notFoo", "namespace", "bar")},
			},
		),
		Entry("should pass when the shoot uses a supported version of Kubernetes",
			func() {
				shoot.Spec.CloudProfileName = ptr.To("foo")
				shoot.Spec.Kubernetes.Version = "1"
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Shoot uses a Kubernetes version with an allowed classification.", Target: rule.NewTarget("version", "1", "classification", "supported")},
			},
		),
		Entry("should fail when the shoot uses a deprecated version of Kubernetes",
			func() {
				shoot.Spec.CloudProfile = &gardencorev1beta1.CloudProfileReference{
					Name: "foo",
					Kind: "CloudProfile",
				}
				shoot.Spec.Kubernetes.Version = "2"
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Shoot uses a Kubernetes version with a non-allowed classification.", Target: rule.NewTarget("version", "2", "classification", "deprecated")},
			},
		),
		Entry("should fail when the shoot uses a preview version of Kubernetes",
			func() {
				shoot.Spec.CloudProfile = &gardencorev1beta1.CloudProfileReference{
					Name: "foo",
					Kind: "CloudProfile",
				}
				shoot.Spec.Kubernetes.Version = "3"
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Shoot uses a Kubernetes version with a non-allowed classification.", Target: rule.NewTarget("version", "3", "classification", "preview")},
			},
		),
		Entry("should pass when the shoot uses a supported version in the namespaceCloudProfile",
			func() {
				shoot.Spec.CloudProfile = &gardencorev1beta1.CloudProfileReference{
					Name: "foo",
					Kind: "NamespacedCloudProfile",
				}
				shoot.Spec.Kubernetes.Version = "2"
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Shoot uses a Kubernetes version with an allowed classification.", Target: rule.NewTarget("version", "2", "classification", "supported")},
			},
		),
		Entry("should fail when the shoot uses a preview version in the namespaceCloudProfile",
			func() {
				shoot.Spec.CloudProfile = &gardencorev1beta1.CloudProfileReference{
					Name: "foo",
					Kind: "NamespacedCloudProfile",
				}
				shoot.Spec.Kubernetes.Version = "3"
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Shoot uses a Kubernetes version with a non-allowed classification.", Target: rule.NewTarget("version", "3", "classification", "preview")},
			},
		),
		Entry("should fail when the shoot uses a deprecated version in the namespaceCloudProfile",
			func() {
				shoot.Spec.CloudProfile = &gardencorev1beta1.CloudProfileReference{
					Name: "foo",
					Kind: "NamespacedCloudProfile",
				}
				shoot.Spec.Kubernetes.Version = "5"
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Shoot uses a Kubernetes version with a non-allowed classification.", Target: rule.NewTarget("version", "5", "classification", "deprecated")},
			},
		),
		Entry("should error when the shoot uses an unknown version in the namespaceCloudProfile",
			func() {
				shoot.Spec.CloudProfile = &gardencorev1beta1.CloudProfileReference{
					Name: "foo",
					Kind: "NamespacedCloudProfile",
				}
				shoot.Spec.Kubernetes.Version = "1"
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Errored, Message: "kubernetes version not found in namespacedCloudProfile", Target: rule.NewTarget("version", "1")},
			},
		),
		Entry("should fail when the shoot uses an unclassified version in the namespaceCloudProfile",
			func() {
				shoot.Spec.CloudProfile = &gardencorev1beta1.CloudProfileReference{
					Name: "foo",
					Kind: "NamespacedCloudProfile",
				}
				shoot.Spec.Kubernetes.Version = "6"
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Shoot uses an unclassified Kubernetes version", Target: rule.NewTarget("version", "6")},
			},
		),
		Entry("should work correctly with options",
			func() {
				shoot.Spec.CloudProfile = &gardencorev1beta1.CloudProfileReference{
					Name: "foo",
					Kind: "CloudProfile",
				}
				shoot.Spec.Kubernetes.Version = "3"
			},
			&rules.Options1001{
				AllowedClassifications: []gardencorev1beta1.VersionClassification{supportedClassification, previewClassification},
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Shoot uses a Kubernetes version with an allowed classification.", Target: rule.NewTarget("version", "3", "classification", "preview")},
			},
		),
	)

	Describe("#ValidateOptions", func() {
		It("should not error when options are correct", func() {
			options := rules.Options1001{
				AllowedClassifications: []gardencorev1beta1.VersionClassification{
					supportedClassification, previewClassification,
				},
			}

			result := options.Validate()
			Expect(result).To(BeEmpty())
		})
		It("should error when options are incorrect", func() {
			options := rules.Options1001{
				AllowedClassifications: []gardencorev1beta1.VersionClassification{
					supportedClassification,
					fakeClassification,
				},
			}
			result := options.Validate()
			Expect(result).To(Equal(field.ErrorList{
				{
					Type:     field.ErrorTypeNotSupported,
					Field:    "allowedClassifications",
					BadValue: fakeClassification,
					Detail:   "supported values: \"preview\", \"supported\", \"deprecated\"",
				},
			}))
		})
	})
})
