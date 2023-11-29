// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	kubernetesgardener "github.com/gardener/gardener/pkg/client/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/rule"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

func (r *Ruleset) registerV1R11Rules(ruleOptions map[string]config.RuleOptionsConfig) error { //nolint:unused // TODO: add to FromGenericConfig
	runtimeClient, err := client.New(r.RuntimeConfig, client.Options{})
	if err != nil {
		return err
	}

	_, err = client.New(r.GardenConfig, client.Options{Scheme: kubernetesgardener.GardenScheme})
	if err != nil {
		return err
	}

	const (
		ns = "garden"
	)
	rules := []rule.Rule{
		&sharedv1r11.Rule242376{Client: runtimeClient, Namespace: ns, DeploymentName: "virtual-garden-kube-controller-manager", ContainerName: "kube-controller-manager"},
	}

	for i, r := range rules {
		opt, found := ruleOptions[r.ID()]
		if found && opt.Skip != nil && opt.Skip.Enabled {
			rules[i] = rule.NewSkipRule(r.ID(), r.Name(), opt.Skip.Justification, rule.Accepted)
		}
	}

	return r.AddRules(rules...)
}
