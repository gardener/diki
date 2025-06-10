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
)

var _ = Describe("options", func() {
	const labelSelectorOpFoo metav1.LabelSelectorOperator = "Foo"

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
				{
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"fo$o": "bar"},
					},
				},
				{
					LabelSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "foo",
								Operator: labelSelectorOpFoo,
								Values:   []string{"bar"},
							},
						},
					},
				},
				{
					MatchLabels: map[string]string{"foo": "bar"},
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
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
					"Field":  Equal("[].labelSelector"),
					"Detail": Equal("must not be empty"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("[].labelSelector"),
					"Detail": Equal("must not be empty"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("[].labelSelector.matchLabels"),
					"BadValue": Equal("fo$o"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("[].labelSelector.matchExpressions[0].operator"),
					"BadValue": Equal(labelSelectorOpFoo),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeForbidden),
					"Field":  Equal("[].matchLabels"),
					"Detail": Equal("cannot be set when labelSelector is defined"),
				}))))
		})
	})

	DescribeTable("#MatchesObjectSelector", func(objectSelector option.ClusterObjectSelector, objectLabels map[string]string, expected bool) {
		matches, err := objectSelector.Matches(objectLabels)

		Expect(err).ToNot(HaveOccurred())
		Expect(matches).To(Equal(expected))
	},
		Entry("should match with valid labels",
			option.ClusterObjectSelector{
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "bar"},
				},
				MatchLabels: map[string]string{"foo": "baz"},
			},
			map[string]string{"foo": "bar"}, true,
		),
		Entry("should not match with invalid labels",
			option.ClusterObjectSelector{
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "baz"},
				},
				MatchLabels: map[string]string{"foo": "bar"},
			},
			map[string]string{"foo": "bar"}, false,
		),
		Entry("should match with matchLabels when labelSelector is not set",
			option.ClusterObjectSelector{
				MatchLabels: map[string]string{"foo": "bar"},
			},
			map[string]string{"foo": "bar"}, true,
		),
		Entry("should not match with matchLabels with invalid labels",
			option.ClusterObjectSelector{
				MatchLabels: map[string]string{"foo": "baz"},
			},
			map[string]string{"foo": "bar"}, false,
		),
	)

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
				{
					NamespaceLabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
				{
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
				{
					NamespaceLabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
				{},
				{
					NamespaceLabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"fo$o": "bar"},
					},
					LabelSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "foo",
								Operator: labelSelectorOpFoo,
								Values:   []string{"bar"},
							},
						},
					},
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
					"Field":  Equal("[]"),
					"Detail": Equal("both matchLabels and namespaceMatchLabels must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("[]"),
					"Detail": Equal("both matchLabels and namespaceMatchLabels must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("[]"),
					"Detail": Equal("both matchLabels and namespaceMatchLabels must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("[]"),
					"Detail": Equal("both matchLabels and namespaceMatchLabels must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("[]"),
					"Detail": Equal("both labelSelector and namespaceLabelSelector must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("[]"),
					"Detail": Equal("both labelSelector and namespaceLabelSelector must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("[]"),
					"Detail": Equal("both labelSelector and namespaceLabelSelector must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("[].labelSelector.matchExpressions[0].operator"),
					"BadValue": Equal(labelSelectorOpFoo),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("[].namespaceLabelSelector.matchLabels"),
					"BadValue": Equal("fo$o"),
				}))))
		})
	})

	DescribeTable("#MatchesNamespacedObjectSelector", func(namespacedObjectSelector option.NamespacedObjectSelector, objectLabels map[string]string, namespaceLabels map[string]string, expected bool) {
		matches, err := namespacedObjectSelector.Matches(objectLabels, namespaceLabels)

		Expect(err).ToNot(HaveOccurred())
		Expect(matches).To(Equal(expected))
	},
		Entry("should match with valid labels",
			option.NamespacedObjectSelector{
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "bar"},
				},
				NamespaceLabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"bar": "foo"},
				},
				MatchLabels:          map[string]string{"foo": "baz"},
				NamespaceMatchLabels: map[string]string{"baz": "foo"},
			},
			map[string]string{"foo": "bar", "foobar": "foo"}, map[string]string{"bar": "foo"}, true,
		),
		Entry("should not match with invalid labels",
			option.NamespacedObjectSelector{
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "baz"},
				},
				NamespaceLabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"baz": "foo"},
				},
				MatchLabels:          map[string]string{"foo": "bar"},
				NamespaceMatchLabels: map[string]string{"bar": "foo"},
			},
			map[string]string{"foo": "bar"}, map[string]string{"bar": "foo"}, false,
		),
		Entry("should match with matchLabels when labelSelector or namespaceLabelSelector is not set",
			option.NamespacedObjectSelector{
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "baz"},
				},
				MatchLabels:          map[string]string{"foo": "bar"},
				NamespaceMatchLabels: map[string]string{"bar": "foo"},
			},
			map[string]string{"foo": "bar", "foobar": "foo"}, map[string]string{"bar": "foo"}, true,
		),
		Entry("should not match with matchLabels with invalid labels",
			option.NamespacedObjectSelector{
				NamespaceLabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"baz": "foo"},
				},
				MatchLabels:          map[string]string{"foo": "bar"},
				NamespaceMatchLabels: map[string]string{"bar": "foo"},
			},
			map[string]string{"foo": "bar"}, map[string]string{"baz": "foo"}, false,
		),
	)
})
