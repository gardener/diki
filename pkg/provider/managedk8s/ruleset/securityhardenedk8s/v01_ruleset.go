// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package securityhardenedk8s

import (
	"encoding/json"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

func (r *Ruleset) registerV01Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
	c, err := client.New(r.Config, client.Options{})
	if err != nil {
		return err
	}

	opts2008, err := getV01OptionOrNil[rules.Options2008](ruleOptions["2008"].Args)
	if err != nil {
		return fmt.Errorf("rule option 2008 error: %s", err.Error())
	}

	rules := []rule.Rule{
		rule.NewSkipRule(
			"2000",
			"Ingress and egress traffic must be restricted by default.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			"2001",
			"Containers must be forbidden to escalate privileges.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			"2002",
			"Storage Classes should have a \"Delete\" reclaim policy.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			"2003",
			"Pods should use only allowed volume types.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			"2004",
			"Limit the Services of type NodePort.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			"2005",
			"Container images must come from trusted repositories.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			"2006",
			"Limit the use of wildcards in RBAC resources.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			"2007",
			"Limit the use of wildcards in RBAC verbs.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
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

func parseV01Options[O rules.RuleOption](options any) (*O, error) {
	optionsByte, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	var parsedOptions O
	if err := json.Unmarshal(optionsByte, &parsedOptions); err != nil {
		return nil, err
	}

	if val, ok := any(parsedOptions).(option.Option); ok {
		if err := val.Validate().ToAggregate(); err != nil {
			return nil, err
		}
	}

	return &parsedOptions, nil
}

func getV01OptionOrNil[O rules.RuleOption](options any) (*O, error) {
	if options == nil {
		return nil, nil
	}
	return parseV01Options[O](options)
}
