// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"encoding/json"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

func (r *Ruleset) registerV1R11Rules(ruleOptions map[string]config.RuleOptionsConfig) error { //nolint:unused // TODO: add to FromGenericConfig
	Client, err := client.New(r.Config, client.Options{})
	if err != nil {
		return err
	}

	opts242415, err := getV1R11OptionOrNil[v1r11.Options242415](ruleOptions[sharedv1r11.ID242415].Args)
	if err != nil {
		return err
	}

	rules := []rule.Rule{
		&v1r11.Rule242415{
			Logger:  r.Logger().With("rule", sharedv1r11.ID242415),
			Client:  Client,
			Options: opts242415,
		},
	}

	for i, r := range rules {
		opt, found := ruleOptions[r.ID()]
		if found && opt.Skip != nil && opt.Skip.Enabled {
			rules[i] = rule.NewSkipRule(r.ID(), r.Name(), opt.Skip.Justification, rule.Accepted)
		}
	}

	return r.AddRules(rules...)
}

func parseV1R11Options[O v1r11.RuleOption](options any) (*O, error) { //nolint:unused
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

func getV1R11OptionOrNil[O v1r11.RuleOption](options any) (*O, error) { //nolint:unused
	if options == nil {
		return nil, nil
	}
	return parseV1R11Options[O](options)
}
