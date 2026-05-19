// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"sort"

	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider"
)

// ValidateConfig validates a [config.DikiConfig] structurally using registered provider validation functions.
func ValidateConfig(c *config.DikiConfig, validateFuncs map[string]provider.ValidateConfigFunc) field.ErrorList {
	allErrs := field.ErrorList{}
	rootPath := field.NewPath("providers")

	seenProviderIDs := make(map[string]struct{})
	for providerIdx, providerConfig := range c.Providers {
		fldPath := rootPath.Index(providerIdx)

		if _, seen := seenProviderIDs[providerConfig.ID]; seen {
			allErrs = append(allErrs, field.Duplicate(fldPath.Child("id"), providerConfig.ID))
			continue
		}
		seenProviderIDs[providerConfig.ID] = struct{}{}

		validateFunc, ok := validateFuncs[providerConfig.ID]
		if !ok {
			allErrs = append(allErrs, field.NotSupported(fldPath.Child("id"), providerConfig.ID, knownProviderIDs(validateFuncs)))
			continue
		}

		allErrs = append(allErrs, validateFunc(providerConfig, fldPath)...)
	}

	return allErrs
}

func knownProviderIDs(funcs map[string]provider.ValidateConfigFunc) []string {
	ids := make([]string, 0, len(funcs))
	for id := range funcs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
