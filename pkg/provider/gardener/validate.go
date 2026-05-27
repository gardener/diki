// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gardener

import (
	"encoding/json"

	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig"
)

// ValidateProviderConfig validates a Gardener provider configuration structurally.
func ValidateProviderConfig(conf config.ProviderConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	providerArgsByte, err := json.Marshal(conf.Args)
	if err != nil {
		return append(allErrs, field.Invalid(fldPath.Child("args"), conf.Args, err.Error()))
	}

	var args providerArgs
	if err := json.Unmarshal(providerArgsByte, &args); err != nil {
		return append(allErrs, field.Invalid(fldPath.Child("args"), conf.Args, err.Error()))
	}

	if len(args.ShootName) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("args", "shootName"), ""))
	}
	if len(args.ShootNamespace) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("args", "shootNamespace"), ""))
	}

	seenRulesets := make(map[string]struct{})
	for rulesetIdx, rulesetConfig := range conf.Rulesets {
		var (
			rulesetPath = fldPath.Child("rulesets").Index(rulesetIdx)
			rulesetKey  = rulesetConfig.ID + "/" + rulesetConfig.Version
		)
		if _, seen := seenRulesets[rulesetKey]; seen {
			allErrs = append(allErrs, field.Duplicate(rulesetPath, rulesetKey))
			continue
		}
		seenRulesets[rulesetKey] = struct{}{}

		switch rulesetConfig.ID {
		case disak8sstig.RulesetID:
			allErrs = append(allErrs, disak8sstig.ValidateRulesetConfig(rulesetConfig, rulesetPath)...)
		default:
			allErrs = append(allErrs, field.NotSupported(rulesetPath.Child("id"), rulesetConfig.ID, []string{disak8sstig.RulesetID}))
		}
	}

	return allErrs
}
