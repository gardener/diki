// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package securityhardenedshoot

import (
	"fmt"

	gardenerk8s "github.com/gardener/gardener/pkg/client/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider/garden/ruleset/securityhardenedshoot/rules"
	"github.com/gardener/diki/pkg/rule"
)

func (r *Ruleset) registerV01Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
	c, err := client.New(r.Config, client.Options{
		Scheme: gardenerk8s.GardenScheme,
	})
	if err != nil {
		return err
	}

	rules := []rule.Rule{
		rule.NewSkipRule(
			"1000",
			"Shoot clusters should enable required extensions.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			"2000",
			"Shoot clusters must have anonymous authentication disabled for the Kubernetes API server.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
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
		rule.NewSkipRule(
			"2004",
			"Shoot clusters must have ValidatingAdmissionWebhook admission plugin enabled.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			"2005",
			"Shoot clusters must not disable timeouts for Kubelet.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			"2006",
			"Shoot clusters must have static token kubeconfig disabled.",
			"Not implemented.",
			rule.NotImplemented,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			"2007",
			"Shoot clusters must have a PodSecurity admission plugin configured.",
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
