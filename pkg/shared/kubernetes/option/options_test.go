// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package option_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var _ = Describe("options", func() {
	Describe("#ValidateObjectSelector", func() {
		It("should correctly validate labels", func() {
			attributes := []option.ClusterObjectSelector{
				{
					MatchLabels: map[string]string{"foo": "bar."},
				},
				{
					MatchLabels: map[string]string{"at_ta": "bar"},
				},
				{
					MatchLabels: map[string]string{"Valid": "label-pair"},
				},
				{
					MatchLabels: map[string]string{"at$a": "bar"},
				},
				{},
				{
					MatchLabels: map[string]string{},
				},
			}

			var result field.ErrorList
			for _, p := range attributes {
				result = append(result, p.Validate()...)
			}

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("[].matchLabels"),
					"BadValue": Equal("bar."),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("[].matchLabels"),
					"BadValue": Equal("at$a"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("[].matchLabels"),
					"Detail": Equal("must not be empty"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("[].matchLabels"),
					"Detail": Equal("must not be empty"),
				}))))
		})
	})

	Describe("#ValidateNamespacedObjectSelector", func() {
		It("should correctly validate labels", func() {
			attributes := []option.NamespacedObjectSelector{
				{
					NamespaceMatchLabels: map[string]string{"_foo": "bar"},
					MatchLabels:          map[string]string{"foo": "bar."},
				},
				{
					NamespaceMatchLabels: map[string]string{"fo?o": "bar"},
					MatchLabels:          map[string]string{"foo": "bar"},
				},
				{
					NamespaceMatchLabels: map[string]string{"foo": "bar"},
					MatchLabels:          map[string]string{"at_ta": "bar"},
				},
				{
					NamespaceMatchLabels: map[string]string{"this": "is_a"},
					MatchLabels:          map[string]string{"Valid": "label-pair"},
				},
				{
					NamespaceMatchLabels: map[string]string{"foo": "ba/r"},
					MatchLabels:          map[string]string{"at$a": "bar"},
				},
				{
					NamespaceMatchLabels: map[string]string{"label": "value"},
				},
				{
					MatchLabels: map[string]string{"label": "value"},
				},
				{
					NamespaceMatchLabels: map[string]string{},
					MatchLabels:          map[string]string{"at_ta": "bar"},
				},
				{
					NamespaceMatchLabels: map[string]string{"foo": "bar"},
					MatchLabels:          map[string]string{},
				},
			}

			var result field.ErrorList
			for _, p := range attributes {
				result = append(result, p.Validate()...)
			}

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("[].namespaceMatchLabels"),
					"BadValue": Equal("_foo"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("[].matchLabels"),
					"BadValue": Equal("bar."),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("[].namespaceMatchLabels"),
					"BadValue": Equal("fo?o"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("[].namespaceMatchLabels"),
					"BadValue": Equal("ba/r"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("[].matchLabels"),
					"BadValue": Equal("at$a"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("[].namespaceMatchLabels"),
					"Detail": Equal("must not be empty"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("[].namespaceMatchLabels"),
					"Detail": Equal("must not be empty"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("[].matchLabels"),
					"Detail": Equal("must not be empty"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("[].matchLabels"),
					"Detail": Equal("must not be empty"),
				}))))
		})
	})
})
