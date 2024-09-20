// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package hardenedgardenershoot

import (
	"context"
	"fmt"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/rule"
)

func (r *Ruleset) registerV0R0Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
	configScheme := runtime.NewScheme()
	gardencorev1beta1.AddToScheme(configScheme)
	c, err := client.New(r.Config, client.Options{
		Scheme: configScheme,
	})
	if err != nil {
		return err
	}

	shoot := &gardencorev1beta1.Shoot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.args.ShootName,
			Namespace: r.args.ProjectNamespace,
		},
	}

	err = c.Get(context.TODO(), client.ObjectKeyFromObject(shoot), shoot)
	if err != nil {
		return err
	}

	rules := []rule.Rule{
		rule.NewSkipRule(
			"0",
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
