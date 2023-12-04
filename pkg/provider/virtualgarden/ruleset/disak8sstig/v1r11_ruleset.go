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
		ns                = "garden"
		etcdMain          = "virtual-garden-etcd-main"
		etcdEvents        = "virtual-garden-etcd-events"
		kcmDeploymentName = "virtual-garden-kube-controller-manager"
		kcmContainerName  = "kube-controller-manager"
	)
	rules := []rule.Rule{
		&sharedv1r11.Rule242376{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: kcmDeploymentName,
			ContainerName:  kcmContainerName,
		},
		rule.NewSkipRule(
			sharedv1r11.ID242377,
			"The Kubernetes Scheduler must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination (MEDIUM 242376)",
			"The Virtual Garden cluster does not make use of a Kubernetes Scheduler.",
			rule.Skipped,
		),
		&sharedv1r11.Rule242378{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: "virtual-garden-kube-apiserver",
			ContainerName:  "kube-apiserver",
		},
		&sharedv1r11.Rule242379{
			Client:                runtimeClient,
			Namespace:             ns,
			StatefulSetETCDMain:   etcdMain,
			StatefulSetETCDEvents: etcdEvents,
		},
		&sharedv1r11.Rule242380{
			Client:                runtimeClient,
			Namespace:             ns,
			StatefulSetETCDMain:   etcdMain,
			StatefulSetETCDEvents: etcdEvents,
		},
		&sharedv1r11.Rule242381{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: kcmDeploymentName,
			ContainerName:  kcmContainerName,
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
