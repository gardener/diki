// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package option

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/internal/utils"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

// ClusterObjectSelector contains generalized options for matching entities by their attribute labels.
type ClusterObjectSelector struct {
	// Deprecated: This field is deprecated and will be forbidden in a future release.
	// Please configure and use LabelSelector instead.
	MatchLabels   map[string]string     `json:"matchLabels" yaml:"matchLabels"`
	LabelSelector *metav1.LabelSelector `json:"labelSelector" yaml:"labelSelector"`
}

var _ option.Option = (*ClusterObjectSelector)(nil)

// Validate validates that option configurations are correctly defined.
func (s *ClusterObjectSelector) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs field.ErrorList
	)

	if len(s.MatchLabels) == 0 && s.LabelSelector == nil {
		allErrs = append(allErrs, field.Required(fldPath.Child("labelSelector"), "must not be empty"))
	}
	if len(s.MatchLabels) > 0 && s.LabelSelector != nil {
		allErrs = append(allErrs, field.Forbidden(fldPath.Child("matchLabels"), "cannot be set when labelSelector is defined"))
	}

	allErrs = append(allErrs, metav1validation.ValidateLabels(s.MatchLabels, fldPath.Child("matchLabels"))...)
	allErrs = append(allErrs, metav1validation.ValidateLabelSelector(s.LabelSelector, metav1validation.LabelSelectorValidationOptions{}, fldPath.Child("labelSelector"))...)

	return allErrs
}

// Matches returns true if this selector matches the given set of labels.
func (s *ClusterObjectSelector) Matches(objectLabels map[string]string) (bool, error) {
	if s.LabelSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(s.LabelSelector)
		if err != nil {
			return false, err
		}
		return selector.Matches(labels.Set(objectLabels)), nil
	}

	return utils.MatchLabels(objectLabels, s.MatchLabels), nil
}

// NamespacedObjectSelector contains generalized options for matching entities by their attribute labels.
type NamespacedObjectSelector struct {
	// Deprecated: This field is deprecated and will be forbidden in a future release.
	// Please configure and use LabelSelector instead.
	MatchLabels map[string]string `json:"matchLabels" yaml:"matchLabels"`
	// Deprecated: This field is deprecated and will be forbidden in a future release.
	// Please configure and use NamespaceMatchLabels instead.
	NamespaceMatchLabels   map[string]string     `json:"namespaceMatchLabels" yaml:"namespaceMatchLabels"`
	LabelSelector          *metav1.LabelSelector `json:"labelSelector" yaml:"labelSelector"`
	NamespaceLabelSelector *metav1.LabelSelector `json:"namespaceLabelSelector" yaml:"namespaceLabelSelector"`
}

var _ option.Option = (*NamespacedObjectSelector)(nil)

// Validate validates that option configurations are correctly defined. It accepts a [field.Path] parameter with the fldPath.
func (s *NamespacedObjectSelector) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs            field.ErrorList
		usingLabelSelector = s.LabelSelector != nil || s.NamespaceLabelSelector != nil
	)

	if (usingLabelSelector && (s.LabelSelector == nil || s.NamespaceLabelSelector == nil)) ||
		(!usingLabelSelector && len(s.MatchLabels) == 0 && len(s.NamespaceMatchLabels) == 0) {
		allErrs = append(allErrs, field.Required(fldPath, "both labelSelector and namespaceLabelSelector must be set"))
	}
	if usingLabelSelector && (len(s.MatchLabels) > 0 || len(s.NamespaceMatchLabels) > 0) {
		allErrs = append(allErrs, field.Forbidden(fldPath, "matchLabels cannot be set when labelSelectors are used"))
	}
	if !usingLabelSelector && len(s.MatchLabels) == 0 && len(s.NamespaceMatchLabels) > 0 {
		allErrs = append(allErrs, field.Required(fldPath, "both matchLabels and namespaceMatchLabels must be set"))
	}
	if !usingLabelSelector && len(s.MatchLabels) > 0 && len(s.NamespaceMatchLabels) == 0 {
		allErrs = append(allErrs, field.Required(fldPath, "both matchLabels and namespaceMatchLabels must be set"))
	}

	allErrs = append(allErrs, metav1validation.ValidateLabels(s.NamespaceMatchLabels, fldPath.Child("namespaceMatchLabels"))...)
	allErrs = append(allErrs, metav1validation.ValidateLabels(s.MatchLabels, fldPath.Child("matchLabels"))...)
	allErrs = append(allErrs, metav1validation.ValidateLabelSelector(s.LabelSelector, metav1validation.LabelSelectorValidationOptions{}, fldPath.Child("labelSelector"))...)
	allErrs = append(allErrs, metav1validation.ValidateLabelSelector(s.NamespaceLabelSelector, metav1validation.LabelSelectorValidationOptions{}, fldPath.Child("namespaceLabelSelector"))...)
	return allErrs
}

// Matches returns true if this selector matches the given set of labels.
func (s *NamespacedObjectSelector) Matches(objectLabels map[string]string, namespaceLabels map[string]string) (bool, error) {
	if s.LabelSelector != nil && s.NamespaceLabelSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(s.LabelSelector)
		if err != nil {
			return false, err
		}
		namespaceSelector, err := metav1.LabelSelectorAsSelector(s.NamespaceLabelSelector)
		if err != nil {
			return false, err
		}

		return selector.Matches(labels.Set(objectLabels)) && namespaceSelector.Matches(labels.Set(namespaceLabels)), nil
	}

	return utils.MatchLabels(objectLabels, s.MatchLabels) && utils.MatchLabels(namespaceLabels, s.NamespaceMatchLabels), nil
}

// AcceptedClusterObject contains generalized properties for accepting object.
type AcceptedClusterObject struct {
	ClusterObjectSelector
	Justification string `json:"justification" yaml:"justification"`
}

// AcceptedNamespacedObject contains generalized properties for accepting namespaced object.
type AcceptedNamespacedObject struct {
	NamespacedObjectSelector
	Justification string `json:"justification" yaml:"justification"`
}
