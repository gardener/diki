// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package podsecuritystandards

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	internalconfig "github.com/gardener/diki/pkg/internal/config"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/podsecuritystandards/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

func (r *Ruleset) validateV01RuleOptions(ruleOptions map[string]internalconfig.IndexedRuleOptionsConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateV01Options[rules.OptionsPSSB007](ruleOptions["PSS-B007"].Args, fldPath.Index(ruleOptions["PSS-B007"].Index).Child("args"))...)

	return allErrs
}

func (r *Ruleset) registerV01Rules(ruleOptions map[string]config.RuleOptionsConfig) error {
	c, err := client.New(r.Config, client.Options{})
	if err != nil {
		return err
	}

	optsPSSB007, err := getV01OptionOrNil[rules.OptionsPSSB007](ruleOptions["PSS-B007"].Args)
	if err != nil {
		return fmt.Errorf("rule option PSS-B007 error: %s", err.Error())
	}

	rules := []rule.Rule{
		rule.NewSkipRule(
			"PSS-B001",
			"Host Process",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B002",
			"Host Namespaces",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B003",
			"Privileged Containers",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B004",
			"Capabilities (Baseline)",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B005",
			"Host Path Volumes",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B006",
			"Host Ports",
			"Not implemented.",
			rule.NotImplemented,
		),
		&rules.RulePSSB007{
			Client:  c,
			Options: optsPSSB007,
		},
		rule.NewSkipRule(
			"PSS-B008",
			"AppArmor",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B009",
			"SELinux",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B010",
			"/proc Mount Type",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B011",
			"Seccomp (Baseline)",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B012",
			"Sysctls",
			"Not implemented.",
			rule.NotImplemented,
		),

		rule.NewSkipRule(
			"PSS-R001",
			"Volume Types",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-R002",
			"Privilege Escalation",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-R003",
			"Running as Non-root",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-R004",
			"Running as Non-root user",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-R005",
			"Seccomp (Restricted)",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-R006",
			"Capabilities (Restricted)",
			"Not implemented.",
			rule.NotImplemented,
		),
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
	expectedRules := 18
	if len(rules) != expectedRules {
		return fmt.Errorf("revision expects %d registered rules, but got: %d", expectedRules, len(rules))
	}

	return r.AddRules(rules...)
}

func validateV01Options[O rules.RuleOption](options any, fldPath *field.Path) field.ErrorList {
	parsedOptions, err := getV01OptionOrNil[O](options)
	if err != nil {
		return field.ErrorList{
			field.Invalid(fldPath, options, err.Error()),
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
