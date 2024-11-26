// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package option

import (
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

// ObjectSelector contains generalized options for matching entities by their attribute labels.
type ObjectSelector struct {
	MatchLabels map[string]string `json:"matchLabels" yaml:"matchLabels"`
}

// TODO: Implement new Option interface in this package with Validate method, which recieves field.Path.
var _ option.Option = (*ObjectSelector)(nil)

// Validate validates that option configurations are correctly defined.
func (s *ObjectSelector) Validate() field.ErrorList {
	var (
		allErrs  field.ErrorList
		rootPath = field.NewPath("")
	)

	if len(s.MatchLabels) == 0 {
		allErrs = append(allErrs, field.Required(rootPath.Child("matchLabels"), "must not be empty"))
	}

	allErrs = append(allErrs, metav1validation.ValidateLabels(s.MatchLabels, rootPath.Child("matchLabels"))...)

	return allErrs
}

// NamespacedObjectSelector contains generalized options for matching entities by their attribute labels.
type NamespacedObjectSelector struct {
	MatchLabels          map[string]string `json:"matchLabels" yaml:"matchLabels"`
	NamespaceMatchLabels map[string]string `json:"namespaceMatchLabels" yaml:"namespaceMatchLabels"`
}

// TODO: Implement new Option interface in this package with Validate method, which recieves field.Path.
var _ option.Option = (*NamespacedObjectSelector)(nil)

// Validate validates that option configurations are correctly defined.
func (s *NamespacedObjectSelector) Validate() field.ErrorList {
	var (
		allErrs  field.ErrorList
		rootPath = field.NewPath("")
	)

	if len(s.NamespaceMatchLabels) == 0 {
		allErrs = append(allErrs, field.Required(rootPath.Child("namespaceMatchLabels"), "must not be empty"))
	}

	if len(s.MatchLabels) == 0 {
		allErrs = append(allErrs, field.Required(rootPath.Child("matchLabels"), "must not be empty"))
	}

	allErrs = append(allErrs, metav1validation.ValidateLabels(s.NamespaceMatchLabels, rootPath.Child("namespaceMatchLabels"))...)
	allErrs = append(allErrs, metav1validation.ValidateLabels(s.MatchLabels, rootPath.Child("matchLabels"))...)
	return allErrs
}

// AcceptedObject contains generalized properties for accepting object.
type AcceptedObject struct {
	ObjectSelector
	Justification string `json:"justification" yaml:"justification"`
}

// AcceptedNamespacedObject contains generalized properties for accepting namespaced object.
type AcceptedNamespacedObject struct {
	NamespacedObjectSelector
	Justification string `json:"justification" yaml:"justification"`
}
