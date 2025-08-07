// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package option

import (
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

// ClusterObjectSelector contains generalized options for matching entities by their attribute labels.
type ClusterObjectSelector struct {
	MatchLabels map[string]string `json:"matchLabels" yaml:"matchLabels"`
}

// TODO: Implement new Option interface in this package with Validate method, which recieves field.Path.
var _ option.Option = (*ClusterObjectSelector)(nil)

// Validate validates that option configurations are correctly defined.
func (s *ClusterObjectSelector) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs field.ErrorList
	)

	if len(s.MatchLabels) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("matchLabels"), "must not be empty"))
	}

	allErrs = append(allErrs, metav1validation.ValidateLabels(s.MatchLabels, fldPath.Child("matchLabels"))...)

	return allErrs
}

// NamespacedObjectSelector contains generalized options for matching entities by their attribute labels.
type NamespacedObjectSelector struct {
	MatchLabels          map[string]string `json:"matchLabels" yaml:"matchLabels"`
	NamespaceMatchLabels map[string]string `json:"namespaceMatchLabels" yaml:"namespaceMatchLabels"`
}

// TODO: Implement new Option interface in this package with Validate method, which recieves field.Path.
var _ option.Option = (*NamespacedObjectSelector)(nil)

// Validate validates that option configurations are correctly defined. It accepts a [field.Path] parameter with the rootPath.
func (s *NamespacedObjectSelector) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs field.ErrorList
	)

	if len(s.NamespaceMatchLabels) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("namespaceMatchLabels"), "must not be empty"))
	}

	if len(s.MatchLabels) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("matchLabels"), "must not be empty"))
	}

	allErrs = append(allErrs, metav1validation.ValidateLabels(s.NamespaceMatchLabels, fldPath.Child("namespaceMatchLabels"))...)
	allErrs = append(allErrs, metav1validation.ValidateLabels(s.MatchLabels, fldPath.Child("matchLabels"))...)
	return allErrs
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
