// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package option_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"k8s.io/apimachinery/pkg/util/validation/field"

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
			result := options.Validate(nil)
			Expect(result).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":     Equal(field.ErrorTypeInvalid),
				"Field":    Equal("expectedFileOwner.users[0]"),
				"BadValue": Equal("-1"),
			})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInternal),
					"Field":    Equal("expectedFileOwner.groups[0]"),
					"BadValue": BeNil(),
					"Detail":   Equal("strconv.ParseInt: parsing \"\": invalid syntax"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInternal),
					"Field":  Equal("expectedFileOwner.groups[1]"),
					"Detail": Equal("strconv.ParseInt: parsing \"asd\": invalid syntax"),
				})),
			))
		})
	})
	Describe("#ValidatePodSelector", func() {
		It("should correctly validate labels", func() {
			podAttributes := []option.PodSelector{
				{
					NamespaceMatchLabels: map[string]string{"_foo": "bar"},
					PodMatchLabels:       map[string]string{"foo": "bar."},
				},
				{
					NamespaceMatchLabels: map[string]string{"foo?baz": "bar"},
					PodMatchLabels:       map[string]string{"foo": "bar"},
				},
				{
					NamespaceMatchLabels: map[string]string{"foo": "bar"},
					PodMatchLabels:       map[string]string{"at_ta": "bar"},
				},
				{
					NamespaceMatchLabels: map[string]string{"this": "is_a"},
					PodMatchLabels:       map[string]string{"Valid": "label-pair"},
				},
				{
					NamespaceMatchLabels: map[string]string{"foo": "ba/r"},
					PodMatchLabels:       map[string]string{"at$a": "bar"},
				},
				{
					NamespaceMatchLabels: map[string]string{"label": "value"},
				},
				{
					PodMatchLabels: map[string]string{"label": "value"},
				},
				{
					NamespaceMatchLabels: map[string]string{},
					PodMatchLabels:       map[string]string{"at_ta": "bar"},
				},
				{
					NamespaceMatchLabels: map[string]string{"foo": "bar"},
					PodMatchLabels:       map[string]string{},
				},
			}

			var result field.ErrorList
			for _, p := range podAttributes {
				result = append(result, p.Validate(nil)...)
			}

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("namespaceMatchLabels"),
					"BadValue": Equal("_foo"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("podMatchLabels"),
					"BadValue": Equal("bar."),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("namespaceMatchLabels"),
					"BadValue": Equal("foo?baz"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("namespaceMatchLabels"),
					"BadValue": Equal("ba/r"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("podMatchLabels"),
					"BadValue": Equal("at$a"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("namespaceMatchLabels"),
					"Detail": Equal("must not be empty"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("namespaceMatchLabels"),
					"Detail": Equal("must not be empty"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("podMatchLabels"),
					"Detail": Equal("must not be empty"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("podMatchLabels"),
					"Detail": Equal("must not be empty"),
				}))))
		})
	})
	Describe("#ValidateOptions242414", func() {
		It("should correctly validate options", func() {
			options := option.Options242414{
				AcceptedPods: []option.AcceptedPods242414{
					{
						PodSelector: option.PodSelector{
							PodMatchLabels: map[string]string{
								"foo": "bar",
							},
							NamespaceMatchLabels: map[string]string{
								"foo": "bar",
							},
						},
					},
					{
						PodSelector: option.PodSelector{
							PodMatchLabels: map[string]string{
								"foo": "bar",
							},
							NamespaceMatchLabels: map[string]string{
								"foo": "bar",
							},
						},
						Ports: []int32{0, 100},
					},
					{
						PodSelector: option.PodSelector{
							PodMatchLabels: map[string]string{
								"foo": "bar",
							},
							NamespaceMatchLabels: map[string]string{
								"foo": "bar",
							},
						},
						Ports: []int32{-1},
					},
				},
			}

			result := options.Validate(nil)

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("acceptedPods[0].ports"),
					"Detail": Equal("must not be empty"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods[2].ports[0]"),
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
						PodSelector: option.PodSelector{
							PodMatchLabels: map[string]string{
								"foo": "bar",
							},
							NamespaceMatchLabels: map[string]string{
								"foo": "bar",
							},
						},
						EnvironmentVariables: []string{"asd=dsa"},
					},
					{
						PodSelector: option.PodSelector{
							PodMatchLabels: map[string]string{
								"foo": "bar",
							},
							NamespaceMatchLabels: map[string]string{
								"foo": "bar",
							},
						},
					},
				},
			}

			result := options.Validate(nil)

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods[0].environmentVariables[0]"),
					"BadValue": Equal("asd=dsa"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("acceptedPods[1].environmentVariables"),
					"Detail": Equal("must not be empty"),
				})),
			))
		})
	})

	Describe("#ValidateOptions242442", func() {
		It("should deny empty expected images list", func() {
			options := option.Options242442{}

			result := options.Validate(nil)

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("expectedVersionedImages"),
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

			result := options.Validate(nil)

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("expectedVersionedImages[1].name"),
					"Detail": Equal("must not be empty"),
				})),
			))
		})
	})
})
