// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"slices"
	"sort"

	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/rule"
)

// ValidateConfig validates a [config.DikiConfig] structurally using registered provider validation functions.
func ValidateConfig(c *config.DikiConfig, validateFuncs map[string]provider.ValidateConfigFunc) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateOutput(c.Output, field.NewPath("output"))...)

	rootPath := field.NewPath("providers")
	knownIDs := knownProviderIDs(validateFuncs)
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
			allErrs = append(allErrs, field.NotSupported(fldPath.Child("id"), providerConfig.ID, knownIDs))
			continue
		}

		allErrs = append(allErrs, validateFunc(providerConfig, fldPath)...)
	}

	return allErrs
}

func validateOutput(output *config.OutputConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if output == nil || len(output.MinStatus) == 0 {
		return allErrs
	}

	statuses := rule.Statuses()
	if slices.Contains(statuses, rule.Status(output.MinStatus)) {
		return allErrs
	}
	statusStrings := make([]string, 0, len(statuses))
	for _, s := range statuses {
		statusStrings = append(statusStrings, string(s))
	}
	return append(allErrs, field.NotSupported(fldPath.Child("minStatus"), output.MinStatus, statusStrings))
}

func knownProviderIDs(funcs map[string]provider.ValidateConfigFunc) []string {
	ids := make([]string, 0, len(funcs))
	for id := range funcs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
