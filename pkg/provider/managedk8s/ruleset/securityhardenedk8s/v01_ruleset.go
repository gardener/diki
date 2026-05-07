// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package securityhardenedk8s

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	internalconfig "github.com/gardener/diki/pkg/internal/config"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

func (r *Ruleset) validateV01RuleOptions(ruleOptions map[string][]internalconfig.IndexedRuleOptionsConfig, fldPath *field.Path) error {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateAllV01Options[rules.Options2000](ruleOptions["2000"], fldPath)...)
	allErrs = append(allErrs, validateAllV01Options[rules.Options2001](ruleOptions["2001"], fldPath)...)
	allErrs = append(allErrs, validateAllV01Options[rules.Options2002](ruleOptions["2002"], fldPath)...)
	allErrs = append(allErrs, validateAllV01Options[rules.Options2003](ruleOptions["2003"], fldPath)...)
	allErrs = append(allErrs, validateAllV01Options[rules.Options2004](ruleOptions["2004"], fldPath)...)
	allErrs = append(allErrs, validateAllV01Options[rules.Options2005](ruleOptions["2005"], fldPath)...)
	allErrs = append(allErrs, validateAllV01Options[rules.Options2006](ruleOptions["2006"], fldPath)...)
	allErrs = append(allErrs, validateAllV01Options[rules.Options2007](ruleOptions["2007"], fldPath)...)
	allErrs = append(allErrs, validateAllV01Options[rules.Options2008](ruleOptions["2008"], fldPath)...)

	return allErrs.ToAggregate()
}

func (r *Ruleset) registerV01Rules(ruleOptions map[string][]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
	c, err := client.New(r.Config, client.Options{})
	if err != nil {
		return err
	}

	opts2000, err := getV01MergedOptionOrNil[rules.Options2000](ruleOptions["2000"])
	if err != nil {
		return fmt.Errorf("rule option 2000 error: %s", err.Error())
	}
	opts2001, err := getV01MergedOptionOrNil[rules.Options2001](ruleOptions["2001"])
	if err != nil {
		return fmt.Errorf("rule option 2001 error: %s", err.Error())
	}
	opts2002, err := getV01MergedOptionOrNil[rules.Options2002](ruleOptions["2002"])
	if err != nil {
		return fmt.Errorf("rule option 2002 error: %s", err.Error())
	}
	opts2003, err := getV01MergedOptionOrNil[rules.Options2003](ruleOptions["2003"])
	if err != nil {
		return fmt.Errorf("rule option 2003 error: %s", err.Error())
	}
	opts2004, err := getV01MergedOptionOrNil[rules.Options2004](ruleOptions["2004"])
	if err != nil {
		return fmt.Errorf("rule option 2004 error: %s", err.Error())
	}
	opts2005, err := getV01MergedOptionOrNil[rules.Options2005](ruleOptions["2005"])
	if err != nil {
		return fmt.Errorf("rule option 2005 error: %s", err.Error())
	}
	opts2006, err := getV01MergedOptionOrNil[rules.Options2006](ruleOptions["2006"])
	if err != nil {
		return fmt.Errorf("rule option 2006 error: %s", err.Error())
	}
	opts2007, err := getV01MergedOptionOrNil[rules.Options2007](ruleOptions["2007"])
	if err != nil {
		return fmt.Errorf("rule option 2007 error: %s", err.Error())
	}
	opts2008, err := getV01MergedOptionOrNil[rules.Options2008](ruleOptions["2008"])
	if err != nil {
		return fmt.Errorf("rule option 2008 error: %s", err.Error())
	}

	rules := []rule.Rule{
		&rules.Rule2000{
			Client:  c,
			Options: opts2000,
		},
		&rules.Rule2001{
			Client:  c,
			Options: opts2001,
		},
		&rules.Rule2002{
			Client:  c,
			Options: opts2002,
		},
		&rules.Rule2003{
			Client:  c,
			Options: opts2003,
		},
		&rules.Rule2004{
			Client:  c,
			Options: opts2004,
		},
		&rules.Rule2005{
			Client:  c,
			Options: opts2005,
		},
		&rules.Rule2006{
			Client:  c,
			Options: opts2006,
		},
		&rules.Rule2007{
			Client:  c,
			Options: opts2007,
		},
		&rules.Rule2008{
			Client:  c,
			Options: opts2008,
		},
	}

	for i, r := range rules {
		var severityLevel rule.SeverityLevel
		if severity, ok := r.(rule.Severity); !ok {
			return fmt.Errorf("rule %s does not implement rule.Severity", r.ID())
		} else {
			severityLevel = severity.Severity()
		}

		if skip := getSkipConfig(ruleOptions[r.ID()]); skip != nil && skip.Enabled {
			rules[i] = rule.NewSkipRule(r.ID(), r.Name(), skip.Justification, rule.Accepted, rule.SkipRuleWithSeverity(severityLevel))
		}
	}

	// check that the registered rules equal
	// the number of rules in that ruleset version
	if len(rules) != 9 {
		return fmt.Errorf("revision expects 9 registered rules, but got: %d", len(rules))
	}

	return r.AddRules(rules...)
}

func validateAllV01Options[O rules.RuleOption](indexedOpts []internalconfig.IndexedRuleOptionsConfig, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList
	for _, indexed := range indexedOpts {
		allErrs = append(allErrs, validateV01Options[O](indexed.Args, fldPath.Index(indexed.Index).Child("args"))...)
	}
	return allErrs
}

func validateV01Options[O rules.RuleOption](options any, fldPath *field.Path) field.ErrorList {
	parsedOptions, err := getV01OptionOrNil[O](options)
	if err != nil {
		return field.ErrorList{
			field.InternalError(fldPath, err),
		}
	}

	if parsedOptions == nil {
		return nil
	}

	if val, ok := any(parsedOptions).(option.Option); ok {
		return val.Validate(fldPath)
	}

	return nil
}

func getV01MergedOptionOrNil[O rules.RuleOption](opts []config.RuleOptionsConfig) (*O, error) {
	if len(opts) == 0 {
		return nil, nil
	}

	first, err := getV01OptionOrNil[O](opts[0].Args)
	if err != nil {
		return nil, err
	}

	if len(opts) == 1 {
		return first, nil
	}

	// Multiple entries — check if the type supports merging.
	mergeable, isMergeable := any(first).(option.MergeableOption)
	if !isMergeable {
		return nil, fmt.Errorf("multiple rule option entries provided but options type %T does not implement MergeableOption", first)
	}

	for _, opt := range opts[1:] {
		parsed, err := getV01OptionOrNil[O](opt.Args)
		if err != nil {
			return nil, err
		}
		if parsed == nil {
			continue
		}

		merged, err := mergeable.Merge(any(parsed).(option.MergeableOption))
		if err != nil {
			return nil, err
		}
		mergeable = merged
	}

	result, ok := any(mergeable).(*O)
	if !ok {
		return nil, fmt.Errorf("merged options type %T is not *%T", mergeable, *new(O))
	}
	return result, nil
}

func getSkipConfig(opts []config.RuleOptionsConfig) *config.RuleOptionSkipConfig {
	for _, opt := range opts {
		if opt.Skip != nil && opt.Skip.Enabled {
			return opt.Skip
		}
	}
	return nil
}

func parseV01Options[O rules.RuleOption](options any) (*O, error) {
	optionsByte, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	var parsedOptions O
	if err := json.Unmarshal(optionsByte, &parsedOptions); err != nil {
		return nil, err
	}

	return &parsedOptions, nil
}

func getV01OptionOrNil[O rules.RuleOption](options any) (*O, error) {
	if options == nil {
		return nil, nil
	}
	return parseV01Options[O](options)
}
