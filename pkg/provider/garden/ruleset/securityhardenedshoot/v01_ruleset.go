// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
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
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

func (r *Ruleset) validateV01RuleOptions(ruleOptions map[string]internalconfig.IndexedRuleOptionsConfig, fldPath *field.Path) error {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateV01Options[rules.Options1000](ruleOptions["1000"].Args, fldPath.Index(ruleOptions["1000"].Index).Child("args"))...)
	allErrs = append(allErrs, validateV01Options[rules.Options2000](ruleOptions["2000"].Args, fldPath.Index(ruleOptions["2000"].Index).Child("args"))...)
	allErrs = append(allErrs, validateV01Options[rules.Options2000](ruleOptions["2007"].Args, fldPath.Index(ruleOptions["2007"].Index).Child("args"))...)

	return allErrs.ToAggregate()
}

func (r *Ruleset) registerV01Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
	c, err := client.New(r.Config, client.Options{
		Scheme: gardenerk8s.GardenScheme,
	})
	if err != nil {
		return err
	}

	opts1000, err := getV01OptionOrNil[rules.Options1000](ruleOptions["1000"].Args)
	if err != nil {
		return fmt.Errorf("rule option 1000 error: %s", err.Error())
	}
	opts2000, err := getV02OptionOrNil[rules.Options2000](ruleOptions["2000"].Args)
	if err != nil {
		return fmt.Errorf("rule option 2000 error: %s", err.Error())
	}
	opts2007, err := getV01OptionOrNil[rules.Options2007](ruleOptions["2007"].Args)
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
		rule.NewSkipRule(
			"2006",
			"Shoot clusters must have static token kubeconfig disabled.",
			// spec.kubernetes.kubelet.enableStaticTokenKubeconfig cannot be set to true since Gardener v1.114.0. ref https://github.com/gardener/gardener/pull/10664
			"Option spec.kubernetes.kubelet.enableStaticTokenKubeconfig cannot be set to true since Gardener v1.114.0.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
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
	if len(rules) != 9 {
		return fmt.Errorf("revision expects 9 registered rules, but got: %d", len(rules))
	}

	return r.AddRules(rules...)
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
