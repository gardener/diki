// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package option

import (
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

// NamespacedObjectSelector contains generalized options for matching entities by their attribute labels
type NamespacedObjectSelector struct {
	MatchLabels          map[string]string `json:"matchLabels" yaml:"matchLabels"`
	NamespaceMatchLabels map[string]string `json:"namespaceMatchLabels" yaml:"namespaceMatchLabels"`
}

var _ option.Option = (*NamespacedObjectSelector)(nil)

// Validate validates that option configurations are correctly defined
func (e NamespacedObjectSelector) Validate() field.ErrorList {
	var (
		allErrs  field.ErrorList
		rootPath = field.NewPath("")
	)

	if len(e.NamespaceMatchLabels) == 0 {
		allErrs = append(allErrs, field.Required(rootPath.Child("namespaceMatchLabels"), "must not be empty"))
	}

	if len(e.MatchLabels) == 0 {
		allErrs = append(allErrs, field.Required(rootPath.Child("matchLabels"), "must not be empty"))
	}

	allErrs = append(allErrs, metav1validation.ValidateLabels(e.NamespaceMatchLabels, rootPath.Child("namespaceMatchLabels"))...)
	allErrs = append(allErrs, metav1validation.ValidateLabels(e.MatchLabels, rootPath.Child("matchLabels"))...)
	return allErrs
}
