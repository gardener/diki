// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package securityhardenedshoot

import (
	"encoding/json"
	"fmt"

	gardenerk8s "github.com/gardener/gardener/pkg/client/kubernetes"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	internalconfig "github.com/gardener/diki/pkg/internal/config"
	"github.com/gardener/diki/pkg/provider/garden/ruleset/securityhardenedshoot/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

func (r *Ruleset) validateV02RuleOptions(ruleOptions map[string]internalconfig.IndexedRuleOptionsConfig, fldPath *field.Path) error {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateV02Options[rules.Options1000](ruleOptions["1000"].Args, fldPath.Index(ruleOptions["1000"].Index).Child("args"))...)
	allErrs = append(allErrs, validateV02Options[rules.Options1001](ruleOptions["1001"].Args, fldPath.Index(ruleOptions["1001"].Index).Child("args"))...)
	allErrs = append(allErrs, validateV02Options[rules.Options1002](ruleOptions["1002"].Args, fldPath.Index(ruleOptions["1002"].Index).Child("args"))...)
	allErrs = append(allErrs, validateV02Options[rules.Options1003](ruleOptions["1003"].Args, fldPath.Index(ruleOptions["1003"].Index).Child("args"))...)
	allErrs = append(allErrs, validateV02Options[rules.Options2000](ruleOptions["2000"].Args, fldPath.Index(ruleOptions["2000"].Index).Child("args"))...)
	allErrs = append(allErrs, validateV02Options[rules.Options2007](ruleOptions["2007"].Args, fldPath.Index(ruleOptions["2007"].Index).Child("args"))...)

	return allErrs.ToAggregate()
}

func (r *Ruleset) registerV02Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
	c, err := client.New(r.Config, client.Options{
		Scheme: gardenerk8s.GardenScheme,
	})
	if err != nil {
		return err
	}

	opts1000, err := getV02OptionOrNil[rules.Options1000](ruleOptions["1000"].Args)
	if err != nil {
		return fmt.Errorf("rule option 1000 error: %s", err.Error())
	}
	opts1001, err := getV02OptionOrNil[rules.Options1001](ruleOptions["1001"].Args)
	if err != nil {
		return fmt.Errorf("rule option 1001 error: %s", err.Error())
	}
	opts1002, err := getV02OptionOrNil[rules.Options1002](ruleOptions["1002"].Args)
	if err != nil {
		return fmt.Errorf("rule option 1002 error: %s", err.Error())
	}
	opts1003, err := getV02OptionOrNil[rules.Options1003](ruleOptions["1003"].Args)
	if err != nil {
		return fmt.Errorf("rule option 1003 error: %s", err.Error())
	}
	opts2000, err := getV02OptionOrNil[rules.Options2000](ruleOptions["2000"].Args)
	if err != nil {
		return fmt.Errorf("rule option 2000 error: %s", err.Error())
	}
	opts2007, err := getV02OptionOrNil[rules.Options2007](ruleOptions["2007"].Args)
	if err != nil {
		return fmt.Errorf("rule option 2007 error: %s", err.Error())
	}

	rules := []rule.Rule{
		&rules.Rule1000{
			Client:         c,
			ShootName:      r.args.ShootName,
			ShootNamespace: r.args.ProjectNamespace,
			Options:        opts1000,
		},
		&rules.Rule1001{
			Client:         c,
			ShootName:      r.args.ShootName,
			ShootNamespace: r.args.ProjectNamespace,
			Options:        opts1001,
		},
		&rules.Rule1002{
			Client:         c,
			ShootName:      r.args.ShootName,
			ShootNamespace: r.args.ProjectNamespace,
			Options:        opts1002,
		},
		&rules.Rule1003{
			Client:         c,
			ShootName:      r.args.ShootName,
			ShootNamespace: r.args.ProjectNamespace,
			Options:        opts1003,
		},
		&rules.Rule2000{
			Client:         c,
			ShootName:      r.args.ShootName,
			ShootNamespace: r.args.ProjectNamespace,
			Options:        opts2000,
		},
		&rules.Rule2001{
			Client:         c,
			ShootName:      r.args.ShootName,
			ShootNamespace: r.args.ProjectNamespace,
		},
		&rules.Rule2002{
			Client:         c,
			ShootName:      r.args.ShootName,
			ShootNamespace: r.args.ProjectNamespace,
		},
		&rules.Rule2003{
			Client:         c,
			ShootName:      r.args.ShootName,
			ShootNamespace: r.args.ProjectNamespace,
		},
		&rules.Rule2004{
			Client:         c,
			ShootName:      r.args.ShootName,
			ShootNamespace: r.args.ProjectNamespace,
		},
		&rules.Rule2005{
			Client:         c,
			ShootName:      r.args.ShootName,
			ShootNamespace: r.args.ProjectNamespace,
		},
		&rules.Rule2007{
			Client:         c,
			Options:        opts2007,
			ShootName:      r.args.ShootName,
			ShootNamespace: r.args.ProjectNamespace,
		},
	}

	for i, r := range rules {
		var severityLevel rule.SeverityLevel
		if severity, ok := r.(rule.Severity); !ok {
			return fmt.Errorf("rule %s does not implement rule.Severity", r.ID())
		} else {
			severityLevel = severity.Severity()
		}

		opt, found := ruleOptions[r.ID()]
		if found && opt.Skip != nil && opt.Skip.Enabled {
			rules[i] = rule.NewSkipRule(r.ID(), r.Name(), opt.Skip.Justification, rule.Accepted, rule.SkipRuleWithSeverity(severityLevel))
		}
	}

	// check that the registered rules equal
	// the number of rules in that ruleset version
	if len(rules) != 11 {
		return fmt.Errorf("revision expects 11 registered rules, but got: %d", len(rules))
	}

	return r.AddRules(rules...)
}

func validateV02Options[O rules.RuleOption](options any, fldPath *field.Path) field.ErrorList {
	parsedOptions, err := getV02OptionOrNil[O](options)
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

func parseV02Options[O rules.RuleOption](options any) (*O, error) {
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

func getV02OptionOrNil[O rules.RuleOption](options any) (*O, error) {
	if options == nil {
		return nil, nil
	}
	return parseV02Options[O](options)
}
