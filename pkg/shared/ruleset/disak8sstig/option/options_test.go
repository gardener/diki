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

	"github.com/gardener/diki/pkg/shared/kubernetes/option"
	disaoption "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ = Describe("options", func() {
	Describe("#ValidateFileOwnerOptions", func() {
		It("should correctly validate options", func() {
			options := disaoption.FileOwnerOptions{
				ExpectedFileOwner: disaoption.ExpectedOwner{
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
					"Type":     Equal(field.ErrorTypeInternal),
					"Field":    Equal("foo.expectedFileOwner.groups[0]"),
					"BadValue": BeNil(),
					"Detail":   Equal("strconv.ParseInt: parsing \"\": invalid syntax"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInternal),
					"Field":  Equal("foo.expectedFileOwner.groups[1]"),
					"Detail": Equal("strconv.ParseInt: parsing \"asd\": invalid syntax"),
				})),
			))
		})
	})
	Describe("#ValidateOptions242414", func() {
		It("should correctly validate options", func() {
			options := disaoption.Options242414{
				AcceptedPods: []disaoption.AcceptedPods242414{
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
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
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
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
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
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
			options := disaoption.Options242415{
				AcceptedPods: []disaoption.AcceptedPods242415{
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
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
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
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
			options := disaoption.Options242442{}

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
			options := disaoption.Options242442{
				ExpectedVersionedImages: []disaoption.ExpectedVersionedImage{
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
})
