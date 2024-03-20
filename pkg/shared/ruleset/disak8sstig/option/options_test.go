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

			result := options.Validate()

			Expect(result).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":     Equal(field.ErrorTypeInvalid),
				"Field":    Equal("expectedFileOwner.users"),
				"BadValue": Equal("-1"),
			})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInternal),
					"Field":    Equal("expectedFileOwner.groups"),
					"BadValue": BeNil(),
					"Detail":   Equal("strconv.ParseInt: parsing \"\": invalid syntax"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeInternal),
					"Field":  Equal("expectedFileOwner.groups"),
					"Detail": Equal("strconv.ParseInt: parsing \"asd\": invalid syntax"),
				})),
			))
		})
	})
	Describe("#ValidateOptions242414", func() {
		It("should correctly validate options", func() {
			options := option.Options242414{
				AcceptedPods: []option.AcceptedPods242414{
					{
						PodMatchLabels: map[string]string{},
						NamespaceMatchLabels: map[string]string{
							"foo": "bar",
						},
					},
					{
						PodMatchLabels: map[string]string{
							"-foo": "bar",
						},
						NamespaceMatchLabels: map[string]string{
							"foo": "!bar",
						},
						Ports: []int32{0, 100},
					},
					{
						PodMatchLabels: map[string]string{
							"foo": "?bar",
						},
						NamespaceMatchLabels: map[string]string{
							".foo": "bar",
						},
						Ports: []int32{-1},
					},
				},
			}

			result := options.Validate()

			Expect(result).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":     Equal(field.ErrorTypeInvalid),
				"Field":    Equal("acceptedPods.podMatchLabels"),
				"BadValue": Equal("-foo"),
			})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods.namespaceMatchLabels"),
					"BadValue": Equal("!bar"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods.podMatchLabels"),
					"BadValue": Equal("?bar"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods.namespaceMatchLabels"),
					"BadValue": Equal(".foo"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("acceptedPods.ports"),
					"Detail": Equal("must not be empty"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods.ports"),
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
						PodMatchLabels: map[string]string{},
						NamespaceMatchLabels: map[string]string{
							"foo": "bar",
						},
						EnvironmentVariables: []string{"asd"},
					},
					{
						PodMatchLabels: map[string]string{
							"-foo": "bar",
						},
						NamespaceMatchLabels: map[string]string{
							"foo": "!bar",
						},
					},
					{
						PodMatchLabels: map[string]string{
							"foo": "?bar",
						},
						NamespaceMatchLabels: map[string]string{
							".foo": "bar",
						},
						EnvironmentVariables: []string{"asd=dsa"},
					},
				},
			}

			result := options.Validate()

			Expect(result).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":     Equal(field.ErrorTypeInvalid),
				"Field":    Equal("acceptedPods.podMatchLabels"),
				"BadValue": Equal("-foo"),
			})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods.namespaceMatchLabels"),
					"BadValue": Equal("!bar"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods.podMatchLabels"),
					"BadValue": Equal("?bar"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods.namespaceMatchLabels"),
					"BadValue": Equal(".foo"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("acceptedPods.environmentVariables"),
					"Detail": Equal("must not be empty"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods.environmentVariables"),
					"BadValue": Equal("asd=dsa"),
				})),
			))
		})
	})
})
