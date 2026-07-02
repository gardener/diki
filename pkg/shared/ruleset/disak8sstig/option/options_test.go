// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package option_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	k8soption "github.com/gardener/diki/pkg/shared/kubernetes/option"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ = Describe("options", func() {
	Describe("#ValidateFileOwnerOptions", func() {
		It("should correctly validate options", func() {
			options := option.FileOwnerOptions{
				ExpectedFileOwner: option.ExpectedOwner{
					Users:  []string{"-1", "0", "100"},
					Groups: []string{"", "asd", "111"},
				},
			}
			result := options.Validate(field.NewPath("foo"))
			Expect(result).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":     Equal(field.ErrorTypeInvalid),
				"Field":    Equal("foo.expectedFileOwner.users[0]"),
				"BadValue": Equal("-1"),
			})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.expectedFileOwner.groups[0]"),
					"BadValue": Equal(""),
					"Detail":   Equal("strconv.ParseInt: parsing \"\": invalid syntax"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.expectedFileOwner.groups[1]"),
					"BadValue": Equal("asd"),
					"Detail":   Equal("strconv.ParseInt: parsing \"asd\": invalid syntax"),
				})),
			))
		})
	})
	Describe("#ValidateOptions242414", func() {
		It("should correctly validate options", func() {
			options := option.Options242414{
				AcceptedPods: []option.AcceptedPods242414{
					{
						AcceptedNamespacedObject: k8soption.AcceptedNamespacedObject{
							NamespacedObjectSelector: k8soption.NamespacedObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"foo": "bar"},
								},
								NamespaceLabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"foo": "bar"},
								},
							},
						},
					},
					{
						AcceptedNamespacedObject: k8soption.AcceptedNamespacedObject{
							NamespacedObjectSelector: k8soption.NamespacedObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"foo": "bar"},
								},
								NamespaceLabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"foo": "bar"},
								},
							},
						},
						Ports: []int32{0, 100},
					},
					{
						AcceptedNamespacedObject: k8soption.AcceptedNamespacedObject{
							NamespacedObjectSelector: k8soption.NamespacedObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"foo": "bar"},
								},
								NamespaceLabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"foo": "bar"},
								},
							},
						},
						Ports: []int32{-1},
					},
				},
			}

			result := options.Validate(field.NewPath("foo"))

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo.acceptedPods[0].ports"),
					"Detail": Equal("must not be empty"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.acceptedPods[2].ports[0]"),
					"BadValue": Equal(int32(-1)),
					"Detail":   Equal("must not be lower than 0"),
				})),
			))
		})
	})
	Describe("#ValidateOptions242415", func() {
		It("should correctly validate options", func() {
			options := option.Options242415{
				AcceptedPods: []option.AcceptedPods242415{
					{
						AcceptedNamespacedObject: k8soption.AcceptedNamespacedObject{
							NamespacedObjectSelector: k8soption.NamespacedObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"foo": "bar"},
								},
								NamespaceLabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"foo": "bar"},
								},
							},
						},
						EnvironmentVariables: []string{"asd=dsa"},
					},
					{
						AcceptedNamespacedObject: k8soption.AcceptedNamespacedObject{
							NamespacedObjectSelector: k8soption.NamespacedObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"foo": "bar"},
								},
								NamespaceLabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"foo": "bar"},
								},
							},
						},
					},
				},
			}

			result := options.Validate(field.NewPath("foo"))

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.acceptedPods[0].environmentVariables[0]"),
					"BadValue": Equal("asd=dsa"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo.acceptedPods[1].environmentVariables"),
					"Detail": Equal("must not be empty"),
				})),
			))
		})
	})

	Describe("#ValidateOptions242442", func() {
		It("should deny empty expected images list", func() {
			options := option.Options242442{}

			result := options.Validate(field.NewPath("foo"))

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo.expectedVersionedImages"),
					"Detail": Equal("must not be empty"),
				})),
			))
		})

		It("should correctly validate options", func() {
			options := option.Options242442{
				ExpectedVersionedImages: []option.ExpectedVersionedImage{
					{
						Name: "foo",
					},
					{
						Name: "",
					},
					{
						Name: "bar",
					},
				},
			}

			result := options.Validate(field.NewPath("foo"))

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo.expectedVersionedImages[1].name"),
					"Detail": Equal("must not be empty"),
				})),
			))
		})
	})
	Describe("#ValidateKubeProxyOptions", func() {
		It("should validate correctly when ClusterObjectSelector is nil", func() {
			options := option.KubeProxyOptions{}

			result := options.Validate(field.NewPath("foo"))

			Expect(result).To(BeEmpty())
		})

		It("should fail when ClusterObjectSelector is not valid", func() {
			options := option.KubeProxyOptions{
				ClusterObjectSelector: &k8soption.ClusterObjectSelector{
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"foo": "bar",
						},
					},
					MatchLabels: map[string]string{
						"foo": "bar",
					},
				},
			}

			result := options.Validate(field.NewPath("foo"))

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeForbidden),
					"Field":  Equal("foo.matchLabels"),
					"Detail": Equal("cannot be set when labelSelector is defined. For more information, please refer to the migration guide: https://github.com/gardener/diki/tree/main/docs/usage/migrate-selector-rule-options.md"),
				})),
			))
		})
		It("should succeed when ClusterObjectSelector is valid", func() {
			options := option.KubeProxyOptions{
				ClusterObjectSelector: &k8soption.ClusterObjectSelector{
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"foo": "bar",
						},
					},
				},
			}

			result := options.Validate(field.NewPath("foo"))

			Expect(result).To(BeEmpty())
		})
	})

	Describe("#Merge FileOwnerOptions", func() {
		It("should merge by appending Users and Groups", func() {
			base := &option.FileOwnerOptions{
				ExpectedFileOwner: option.ExpectedOwner{
					Users:  []string{"0"},
					Groups: []string{"0"},
				},
			}
			other := &option.FileOwnerOptions{
				ExpectedFileOwner: option.ExpectedOwner{
					Users:  []string{"1000"},
					Groups: []string{"1000"},
				},
			}

			merged, err := base.Merge(other)
			Expect(err).ToNot(HaveOccurred())

			mergedOpts, ok := merged.(*option.FileOwnerOptions)
			Expect(ok).To(BeTrue())
			Expect(mergedOpts.ExpectedFileOwner.Users).To(ConsistOf("0", "1000"))
			Expect(mergedOpts.ExpectedFileOwner.Groups).To(ConsistOf("0", "1000"))
		})

		It("should deduplicate Users and Groups", func() {
			base := &option.FileOwnerOptions{
				ExpectedFileOwner: option.ExpectedOwner{
					Users:  []string{"0", "1000"},
					Groups: []string{"0", "65534"},
				},
			}
			other := &option.FileOwnerOptions{
				ExpectedFileOwner: option.ExpectedOwner{
					Users:  []string{"0", "65534"},
					Groups: []string{"0"},
				},
			}

			merged, err := base.Merge(other)
			Expect(err).ToNot(HaveOccurred())

			mergedOpts, ok := merged.(*option.FileOwnerOptions)
			Expect(ok).To(BeTrue())
			Expect(mergedOpts.ExpectedFileOwner.Users).To(ConsistOf("0", "1000", "65534"))
			Expect(mergedOpts.ExpectedFileOwner.Groups).To(ConsistOf("0", "65534"))
		})

		It("should return the receiver when merging with nil", func() {
			base := &option.FileOwnerOptions{
				ExpectedFileOwner: option.ExpectedOwner{Users: []string{"0"}},
			}
			merged, err := base.Merge(nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(merged).To(Equal(base))
		})

		It("should return error when merging with wrong type", func() {
			base := &option.FileOwnerOptions{}
			_, err := base.Merge(&option.Options242414{})
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("#Merge Options242414", func() {
		It("should merge by appending AcceptedPods", func() {
			base := &option.Options242414{
				AcceptedPods: []option.AcceptedPods242414{
					{Ports: []int32{80}},
				},
			}
			other := &option.Options242414{
				AcceptedPods: []option.AcceptedPods242414{
					{Ports: []int32{443}},
				},
			}

			merged, err := base.Merge(other)
			Expect(err).ToNot(HaveOccurred())

			mergedOpts, ok := merged.(*option.Options242414)
			Expect(ok).To(BeTrue())
			Expect(mergedOpts.AcceptedPods).To(HaveLen(2))
			Expect(mergedOpts.AcceptedPods[0].Ports).To(Equal([]int32{80}))
			Expect(mergedOpts.AcceptedPods[1].Ports).To(Equal([]int32{443}))
		})

		It("should return the receiver when merging with nil", func() {
			base := &option.Options242414{
				AcceptedPods: []option.AcceptedPods242414{{Ports: []int32{80}}},
			}
			merged, err := base.Merge(nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(merged).To(Equal(base))
		})

		It("should return error when merging with wrong type", func() {
			base := &option.Options242414{}
			_, err := base.Merge(&option.FileOwnerOptions{})
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("#Merge Options242415", func() {
		It("should merge by appending AcceptedPods", func() {
			base := &option.Options242415{
				AcceptedPods: []option.AcceptedPods242415{
					{EnvironmentVariables: []string{"FOO"}},
				},
			}
			other := &option.Options242415{
				AcceptedPods: []option.AcceptedPods242415{
					{EnvironmentVariables: []string{"BAR"}},
				},
			}

			merged, err := base.Merge(other)
			Expect(err).ToNot(HaveOccurred())

			mergedOpts, ok := merged.(*option.Options242415)
			Expect(ok).To(BeTrue())
			Expect(mergedOpts.AcceptedPods).To(HaveLen(2))
			Expect(mergedOpts.AcceptedPods[0].EnvironmentVariables).To(Equal([]string{"FOO"}))
			Expect(mergedOpts.AcceptedPods[1].EnvironmentVariables).To(Equal([]string{"BAR"}))
		})

		It("should return the receiver when merging with nil", func() {
			base := &option.Options242415{
				AcceptedPods: []option.AcceptedPods242415{{EnvironmentVariables: []string{"FOO"}}},
			}
			merged, err := base.Merge(nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(merged).To(Equal(base))
		})

		It("should return error when merging with wrong type", func() {
			base := &option.Options242415{}
			_, err := base.Merge(&option.FileOwnerOptions{})
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("#Merge Options242442", func() {
		It("should merge by appending ExpectedVersionedImages", func() {
			base := &option.Options242442{
				ExpectedVersionedImages: []option.ExpectedVersionedImage{
					{Name: "image-a"},
				},
			}
			other := &option.Options242442{
				ExpectedVersionedImages: []option.ExpectedVersionedImage{
					{Name: "image-b"},
				},
			}

			merged, err := base.Merge(other)
			Expect(err).ToNot(HaveOccurred())

			mergedOpts, ok := merged.(*option.Options242442)
			Expect(ok).To(BeTrue())
			Expect(mergedOpts.ExpectedVersionedImages).To(HaveLen(2))
			Expect(mergedOpts.ExpectedVersionedImages[0].Name).To(Equal("image-a"))
			Expect(mergedOpts.ExpectedVersionedImages[1].Name).To(Equal("image-b"))
		})

		It("should return the receiver when merging with nil", func() {
			base := &option.Options242442{
				ExpectedVersionedImages: []option.ExpectedVersionedImage{{Name: "image-a"}},
			}
			merged, err := base.Merge(nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(merged).To(Equal(base))
		})

		It("should return error when merging with wrong type", func() {
			base := &option.Options242442{}
			_, err := base.Merge(&option.FileOwnerOptions{})
			Expect(err).To(HaveOccurred())
		})
	})
})
