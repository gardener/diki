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
						MatchLabels: map[string]string{"foo$bar": "bar"},
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
				result = append(result, p.Validate(field.NewPath("foo"))...)
			}

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.matchLabels"),
					"BadValue": Equal("bar."),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.matchLabels"),
					"BadValue": Equal("at$a"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo.labelSelector"),
					"Detail": Equal("must not be empty"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo.labelSelector"),
					"Detail": Equal("must not be empty"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.labelSelector.matchLabels"),
					"BadValue": Equal("foo$bar"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.labelSelector.matchExpressions[0].operator"),
					"BadValue": Equal(labelSelectorOpFoo),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeForbidden),
					"Field":  Equal("foo.matchLabels"),
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
					NamespaceMatchLabels: map[string]string{"foo?baz": "bar"},
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
						MatchLabels: map[string]string{"foo$bar": "bar"},
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
				{
					NamespaceLabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					MatchLabels: map[string]string{"foo": "bar"},
				},
				{
					NamespaceLabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
					NamespaceMatchLabels: map[string]string{"foo": "bar"},
				},
			}

			var result field.ErrorList
			for _, p := range attributes {
				result = append(result, p.Validate(field.NewPath("foo"))...)
			}

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.namespaceMatchLabels"),
					"BadValue": Equal("_foo"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.matchLabels"),
					"BadValue": Equal("bar."),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.namespaceMatchLabels"),
					"BadValue": Equal("foo?baz"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.namespaceMatchLabels"),
					"BadValue": Equal("ba/r"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.matchLabels"),
					"BadValue": Equal("at$a"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo"),
					"Detail": Equal("both matchLabels and namespaceMatchLabels must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo"),
					"Detail": Equal("both matchLabels and namespaceMatchLabels must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo"),
					"Detail": Equal("both matchLabels and namespaceMatchLabels must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo"),
					"Detail": Equal("both matchLabels and namespaceMatchLabels must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo"),
					"Detail": Equal("both labelSelector and namespaceLabelSelector must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo"),
					"Detail": Equal("both labelSelector and namespaceLabelSelector must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo"),
					"Detail": Equal("both labelSelector and namespaceLabelSelector must be set"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.labelSelector.matchExpressions[0].operator"),
					"BadValue": Equal(labelSelectorOpFoo),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.namespaceLabelSelector.matchLabels"),
					"BadValue": Equal("foo$bar"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeForbidden),
					"Field":  Equal("foo"),
					"Detail": Equal("matchLabels cannot be set when labelSelectors are used"),
				})), PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeForbidden),
					"Field":  Equal("foo"),
					"Detail": Equal("matchLabels cannot be set when labelSelectors are used"),
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

	Describe("#ValidateAcceptedPodVolumes", func() {
		It("should correctly validate an empty list of volume names", func() {
			option := option.AcceptedPodVolumes{
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
			}

			results := option.Validate(field.NewPath("foo"))

			Expect(results).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo.volumeNames"),
					"Detail": Equal("must not be empty"),
				})),
			))
		})

		It("should error when a volume name is empty", func() {
			option := option.AcceptedPodVolumes{
				AcceptedNamespacedObject: option.AcceptedNamespacedObject{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						MatchLabels: map[string]string{
							"foo": "bar",
						},
						NamespaceMatchLabels: map[string]string{
							"foo": "bar",
						},
					},
				},
				VolumeNames: []string{"valid-volume-name-1", "valid-volume-name-2", ""},
			}
			results := option.Validate(field.NewPath("foo"))

			Expect(results).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.volumeNames[2]"),
					"BadValue": Equal(""),
					"Detail":   Equal("must not be empty"),
				})),
			))
		})

		It("should correctly validate volume names", func() {
			option := option.AcceptedPodVolumes{
				AcceptedNamespacedObject: option.AcceptedNamespacedObject{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						MatchLabels: map[string]string{
							"foo": "bar",
						},
						NamespaceMatchLabels: map[string]string{
							"foo": "bar",
						},
					},
				},
				VolumeNames: []string{"valid-volume-name", "invalid-volume-name?", "valid-wildcard*", "*invalid-wildcard-", "*", "valid*wildcard"},
			}

			results := option.Validate(field.NewPath("foo"))

			Expect(results).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.volumeNames[1]"),
					"BadValue": Equal("invalid-volume-name?"),
					"Detail":   Equal("volume name must match regex: ^[a-z0-9*]([-a-z0-9*]*[a-z0-9*])?$"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.volumeNames[3]"),
					"BadValue": Equal("*invalid-wildcard-"),
					"Detail":   Equal("volume name must match regex: ^[a-z0-9*]([-a-z0-9*]*[a-z0-9*])?$"),
				})),
			))
		})

		It("should not error when the volume names are correct", func() {
			option := option.AcceptedPodVolumes{
				AcceptedNamespacedObject: option.AcceptedNamespacedObject{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						MatchLabels: map[string]string{
							"foo": "bar",
						},
						NamespaceMatchLabels: map[string]string{
							"foo": "bar",
						},
					},
				},
				VolumeNames: []string{"valid-volume-name", "volume", "abcde-eeee", "wildcard-volume*"},
			}

			results := option.Validate(field.NewPath("foo"))
			Expect(results).To(BeNil())
		})
	})

	Describe("MatchesAcceptedPodVolumes", func() {
		It("should correctly match the pod with non-matching pod and namespace labels", func() {
			option := option.AcceptedPodVolumes{
				AcceptedNamespacedObject: option.AcceptedNamespacedObject{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
						NamespaceLabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "baz",
							},
						},
					},
					Justification: "accepted pod",
				},
				VolumeNames: []string{"volume-1"},
			}

			matches, err := option.Matches(map[string]string{"foo": "bar"}, map[string]string{"foo": "bar"}, "volume-1")
			Expect(err).To(BeNil())
			Expect(matches).To(BeFalse())
		})

		It("should correctly match the volume names of a pod", func() {
			option := option.AcceptedPodVolumes{
				AcceptedNamespacedObject: option.AcceptedNamespacedObject{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
						NamespaceLabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
					},
					Justification: "accepted pod",
				},
				VolumeNames: []string{"volume-1"},
			}

			matches, err := option.Matches(map[string]string{"foo": "bar"}, map[string]string{"foo": "bar"}, "volume-1")
			Expect(err).To(BeNil())
			Expect(matches).To(BeTrue())
		})

		It("should correctly match the volume names of a pod with a wildcard", func() {
			option := option.AcceptedPodVolumes{
				AcceptedNamespacedObject: option.AcceptedNamespacedObject{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
						NamespaceLabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
					},
					Justification: "accepted pod",
				},
				VolumeNames: []string{"*"},
			}

			matches, err := option.Matches(map[string]string{"foo": "bar"}, map[string]string{"foo": "bar"}, "volume-1")
			Expect(err).To(BeNil())
			Expect(matches).To(BeTrue())
		})

		It("should correctly match the volume names of a pod with a matching partial wildcard", func() {
			option := option.AcceptedPodVolumes{
				AcceptedNamespacedObject: option.AcceptedNamespacedObject{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
						NamespaceLabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
					},
					Justification: "accepted pod",
				},
				VolumeNames: []string{"volume-*"},
			}

			matches, err := option.Matches(map[string]string{"foo": "bar"}, map[string]string{"foo": "bar"}, "volume-1")
			Expect(err).To(BeNil())
			Expect(matches).To(BeTrue())
		})

		It("should correctly match the volume names of a pod with a non-matching partial wildcard", func() {
			option := option.AcceptedPodVolumes{
				AcceptedNamespacedObject: option.AcceptedNamespacedObject{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
						NamespaceLabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
					},
					Justification: "accepted pod",
				},
				VolumeNames: []string{"*-volume"},
			}

			matches, err := option.Matches(map[string]string{"foo": "bar"}, map[string]string{"foo": "bar"}, "volume1")
			Expect(err).To(BeNil())
			Expect(matches).To(BeFalse())
		})

	})
})
