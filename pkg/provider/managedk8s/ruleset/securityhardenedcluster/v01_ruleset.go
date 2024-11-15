// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package securityhardenedcluster

import (
	"fmt"

	gardenerk8s "github.com/gardener/gardener/pkg/client/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/rule"
)

func (r *Ruleset) registerV01Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
	_, err := client.New(r.Config, client.Options{
		Scheme: gardenerk8s.GardenScheme,
	})
	if err != nil {
		return err
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
		rule.NewSkipRule(
			"2008",
			"Pods must not be allowed to mount host directories.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
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
	if len(rules) != 9 {
		return fmt.Errorf("revision expects 9 registered rules, but got: %d", len(rules))
	}

	return r.AddRules(rules...)
}
