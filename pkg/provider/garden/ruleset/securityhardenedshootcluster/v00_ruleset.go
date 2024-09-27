// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package securityhardenedshootcluster

import (
	"fmt"

	gardenerk8s "github.com/gardener/gardener/pkg/client/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/rule"
)

func (r *Ruleset) registerV00Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
	_, err := client.New(r.Config, client.Options{
		Scheme: gardenerk8s.GardenScheme,
	})
	if err != nil {
		return err
	}

	rules := []rule.Rule{
		rule.NewSkipRule(
			"1000",
			"Rule Name",
			"Not implemented.",
			rule.NotImplemented,
		),
	}

	for i, r := range rules {
		opt, found := ruleOptions[r.ID()]
		if found && opt.Skip != nil && opt.Skip.Enabled {
			rules[i] = rule.NewSkipRule(r.ID(), r.Name(), opt.Skip.Justification, rule.Accepted)
		}
	}

	// check that the registered rules equal
	// the number of rules in that ruleset version
	if len(rules) != 1 {
		return fmt.Errorf("revision expects 1 registered rules, but got: %d", len(rules))
	}

	return r.AddRules(rules...)
}
