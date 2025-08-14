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

var _ = Describe("#1002", func() {
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
		ruleName       = "Shoot clusters should use supported versions for their Workers' images."
		ruleID         = "1002"
		severity       = rule.SeverityMedium
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
				MachineImages: []gardencorev1beta1.MachineImage{
					{
						Name: "foo",
						Versions: []gardencorev1beta1.MachineImageVersion{
							{
								ExpirableVersion: gardencorev1beta1.ExpirableVersion{
									Version:        "1",
									Classification: &deprecatedClassification,
								},
							},
							{
								ExpirableVersion: gardencorev1beta1.ExpirableVersion{
									Version:        "2",
									Classification: &supportedClassification,
								},
							},
							{
								ExpirableVersion: gardencorev1beta1.ExpirableVersion{
									Version:        "3",
									Classification: &previewClassification,
								},
							},
						},
					},
					{
						Name: "bar",
						Versions: []gardencorev1beta1.MachineImageVersion{
							{
								ExpirableVersion: gardencorev1beta1.ExpirableVersion{
									Version:        "1",
									Classification: &supportedClassification,
								},
							},
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
				MachineImages: []gardencorev1beta1.MachineImage{
					{
						Name: "foo",
						Versions: []gardencorev1beta1.MachineImageVersion{
							{
								ExpirableVersion: gardencorev1beta1.ExpirableVersion{
									Version:        "4",
									Classification: &supportedClassification,
								},
							},
						},
					},
				},
			},
			Status: gardencorev1beta1.NamespacedCloudProfileStatus{
				CloudProfileSpec: gardencorev1beta1.CloudProfileSpec{
					MachineImages: []gardencorev1beta1.MachineImage{
						{
							Name: "foo",
							Versions: []gardencorev1beta1.MachineImageVersion{
								{
									ExpirableVersion: gardencorev1beta1.ExpirableVersion{
										Version:        "2",
										Classification: &supportedClassification,
									},
								},
								{
									ExpirableVersion: gardencorev1beta1.ExpirableVersion{
										Version:        "3",
										Classification: &previewClassification,
									},
								},
							},
						},
						{
							Name: "bar",
							Versions: []gardencorev1beta1.MachineImageVersion{
								{
									ExpirableVersion: gardencorev1beta1.ExpirableVersion{
										Version: "1",
									},
								},
								{
									ExpirableVersion: gardencorev1beta1.ExpirableVersion{
										Version:        "2",
										Classification: &supportedClassification,
									},
								},
							},
						},
					},
				},
			},
		}

		Expect(fakeClient.Create(ctx, nsCloudProfile)).To(Succeed())
	})

	DescribeTable("Run cases", func(updateFn func(), options *rules.Options1002, expectedCheckResults []rule.CheckResult) {
		updateFn()
		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())

		r = &rules.Rule1002{
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
		Entry("should pass when workers use supported image varsions",
			func() {
				shoot.Spec.CloudProfileName = ptr.To("foo")
				shoot.Spec.Provider.Workers = []gardencorev1beta1.Worker{
					{
						Name: "foo",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "foo",
								Version: ptr.To("2"),
							},
						},
					},
					{
						Name: "foo2",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "bar",
								Version: ptr.To("1"),
							},
						},
					},
				}
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Worker group uses allowed classification of machine image.", Target: rule.NewTarget("worker", "foo", "image", "foo", "version", "2", "classification", "supported")},
				{Status: rule.Passed, Message: "Worker group uses allowed classification of machine image.", Target: rule.NewTarget("worker", "foo2", "image", "bar", "version", "1", "classification", "supported")},
			},
		),
		Entry("should fail when workers use deprecated image varsion",
			func() {
				shoot.Spec.CloudProfile = &gardencorev1beta1.CloudProfileReference{
					Name: "foo",
					Kind: "CloudProfile",
				}
				shoot.Spec.Provider.Workers = []gardencorev1beta1.Worker{
					{
						Name: "foo",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "foo",
								Version: ptr.To("1"),
							},
						},
					},
				}
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Worker group uses not allowed classification of machine image.", Target: rule.NewTarget("worker", "foo", "image", "foo", "version", "1", "classification", "deprecated")},
			},
		),
		Entry("should fail when workers use preview image varsion",
			func() {
				shoot.Spec.CloudProfile = &gardencorev1beta1.CloudProfileReference{
					Name: "foo",
					Kind: "CloudProfile",
				}
				shoot.Spec.Provider.Workers = []gardencorev1beta1.Worker{
					{
						Name: "foo",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "foo",
								Version: ptr.To("3"),
							},
						},
					},
				}
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Worker group uses not allowed classification of machine image.", Target: rule.NewTarget("worker", "foo", "image", "foo", "version", "3", "classification", "preview")},
			},
		),
		Entry("should work correctly with namespacedCloudProfile",
			func() {
				shoot.Spec.CloudProfile = &gardencorev1beta1.CloudProfileReference{
					Name: "foo",
					Kind: "NamespacedCloudProfile",
				}
				shoot.Spec.Provider.Workers = []gardencorev1beta1.Worker{
					{
						Name: "foo1",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "foo",
								Version: ptr.To("1"),
							},
						},
					},
					{
						Name: "foo2",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "foo",
								Version: ptr.To("2"),
							},
						},
					},
					{
						Name: "foo3",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "foo",
								Version: ptr.To("3"),
							},
						},
					},
					{
						Name: "foo4",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "foo",
								Version: ptr.To("4"),
							},
						},
					},
					{
						Name: "bar1",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "bar",
								Version: ptr.To("1"),
							},
						},
					},
					{
						Name: "bar2",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "bar",
								Version: ptr.To("2"),
							},
						},
					},
				}
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Errored, Message: "image version not found in namespacedCloudProfile", Target: rule.NewTarget("worker", "foo1", "image", "foo", "version", "1")},
				{Status: rule.Passed, Message: "Worker group uses allowed classification of machine image.", Target: rule.NewTarget("worker", "foo2", "image", "foo", "version", "2", "classification", "supported")},
				{Status: rule.Failed, Message: "Worker group uses not allowed classification of machine image.", Target: rule.NewTarget("worker", "foo3", "image", "foo", "version", "3", "classification", "preview")},
				{Status: rule.Passed, Message: "Worker group uses allowed classification of machine image.", Target: rule.NewTarget("worker", "foo4", "image", "foo", "version", "4", "classification", "supported")},
				{Status: rule.Failed, Message: "Worker group uses image with unclassified image.", Target: rule.NewTarget("worker", "bar1", "image", "bar", "version", "1")},
				{Status: rule.Passed, Message: "Worker group uses allowed classification of machine image.", Target: rule.NewTarget("worker", "bar2", "image", "bar", "version", "2", "classification", "supported")},
			},
		),
		Entry("should work correctly with options",
			func() {
				shoot.Spec.CloudProfile = &gardencorev1beta1.CloudProfileReference{
					Name: "foo",
					Kind: "CloudProfile",
				}
				shoot.Spec.Provider.Workers = []gardencorev1beta1.Worker{
					{
						Name: "foo1",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "foo",
								Version: ptr.To("1"),
							},
						},
					},
					{
						Name: "foo2",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "foo",
								Version: ptr.To("2"),
							},
						},
					},
					{
						Name: "foo3",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "foo",
								Version: ptr.To("3"),
							},
						},
					},
					{
						Name: "foo4",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "foo",
								Version: ptr.To("4"),
							},
						},
					},
					{
						Name: "bar",
						Machine: gardencorev1beta1.Machine{
							Image: &gardencorev1beta1.ShootMachineImage{
								Name:    "bar",
								Version: ptr.To("1"),
							},
						},
					},
				}
			},
			&rules.Options1002{
				MachineImages: []rules.MachineImage{
					{
						Name:                   "foo",
						AllowedClassifications: []gardencorev1beta1.VersionClassification{supportedClassification, previewClassification},
					},
					{
						Name:                   "bar",
						AllowedClassifications: []gardencorev1beta1.VersionClassification{previewClassification},
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Worker group uses not allowed classification of machine image.", Target: rule.NewTarget("worker", "foo1", "image", "foo", "version", "1", "classification", "deprecated")},
				{Status: rule.Passed, Message: "Worker group uses allowed classification of machine image.", Target: rule.NewTarget("worker", "foo2", "image", "foo", "version", "2", "classification", "supported")},
				{Status: rule.Passed, Message: "Worker group uses allowed classification of machine image.", Target: rule.NewTarget("worker", "foo3", "image", "foo", "version", "3", "classification", "preview")},
				{Status: rule.Errored, Message: "image version not found in cloudProfile", Target: rule.NewTarget("worker", "foo4", "image", "foo", "version", "4")},
				{Status: rule.Failed, Message: "Worker group uses not allowed classification of machine image.", Target: rule.NewTarget("worker", "bar", "image", "bar", "version", "1", "classification", "supported")},
			},
		),
	)

	Describe("#ValidateOptions", func() {
		It("should not error when options are correct", func() {
			options := rules.Options1002{
				MachineImages: []rules.MachineImage{
					{
						Name: "foo",
						AllowedClassifications: []gardencorev1beta1.VersionClassification{
							supportedClassification, previewClassification,
						},
					},
					{
						Name: "bar",
						AllowedClassifications: []gardencorev1beta1.VersionClassification{
							deprecatedClassification,
						},
					},
				},
			}

			result := options.Validate(nil)
			Expect(result).To(BeEmpty())
		})
		It("should error when options are incorrect", func() {
			options := rules.Options1002{
				MachineImages: []rules.MachineImage{
					{
						Name: "",
						AllowedClassifications: []gardencorev1beta1.VersionClassification{
							previewClassification,
						},
					},
					{
						Name: "bar",
						AllowedClassifications: []gardencorev1beta1.VersionClassification{
							fakeClassification,
						},
					},
				},
			}
			result := options.Validate(nil)
			Expect(result).To(Equal(field.ErrorList{
				{
					Type:     field.ErrorTypeRequired,
					Field:    "machineImages[0].name",
					BadValue: "",
					Detail:   "must not be empty",
				},
				{
					Type:     field.ErrorTypeNotSupported,
					Field:    "machineImages[1].allowedClassifications[0]",
					BadValue: fakeClassification,
					Detail:   "supported values: \"preview\", \"supported\", \"deprecated\"",
				},
			}))
		})
	})
})
