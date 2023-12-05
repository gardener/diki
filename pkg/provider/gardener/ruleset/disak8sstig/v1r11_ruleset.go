// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"encoding/json"

	"github.com/Masterminds/semver"
	kubernetesgardener "github.com/gardener/gardener/pkg/client/kubernetes"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

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

func (r *Ruleset) registerV1R11Rules(ruleOptions map[string]config.RuleOptionsConfig) error { //nolint:unused // TODO: add to FromGenericConfig
	shootClient, err := client.New(r.ShootConfig, client.Options{Scheme: kubernetesgardener.ShootScheme})
	if err != nil {
		return err
	}

	seedClient, err := client.New(r.SeedConfig, client.Options{Scheme: kubernetesgardener.SeedScheme})
	if err != nil {
		return err
	}

	shootPodContext, err := pod.NewSimplePodContext(shootClient, r.ShootConfig)
	if err != nil {
		return err
	}

	seedPodContext, err := pod.NewSimplePodContext(seedClient, r.SeedConfig)
	if err != nil {
		return err
	}

	shootClientSet, err := kubernetes.NewForConfig(r.ShootConfig)
	if err != nil {
		return err
	}

	shootKubernetesVersion, err := shootClientSet.Discovery().ServerVersion()
	if err != nil {
		return err
	}

	semverShootKubernetesVersion, err := semver.NewVersion(shootKubernetesVersion.String())
	if err != nil {
		return err
	}

	seedClientSet, err := kubernetes.NewForConfig(r.SeedConfig)
	if err != nil {
		return err
	}

	seedKubernetesVersion, err := seedClientSet.Discovery().ServerVersion()
	if err != nil {
		return err
	}

	semverSeedKubernetesVersion, err := semver.NewVersion(seedKubernetesVersion.String())
	if err != nil {
		return err
	}

	opts242414, err := getV1R11OptionOrNil[v1r11.Options242414](ruleOptions[v1r11.ID242414].Args)
	if err != nil {
		return err
	}
	opts242415, err := getV1R11OptionOrNil[v1r11.Options242415](ruleOptions[v1r11.ID242415].Args)
	if err != nil {
		return err
	}
	opts245543, err := getV1R11OptionOrNil[v1r11.Options245543](ruleOptions[v1r11.ID245543].Args)
	if err != nil {
		return err
	}
	opts254800, err := getV1R11OptionOrNil[v1r11.Options254800](ruleOptions[v1r11.ID254800].Args)
	if err != nil {
		return err
	}

	optsPodFiles, err := getV1R11OptionOrNil[v1r11.OptionsPodFiles](ruleOptions[v1r11.IDPodFiles].Args)
	if err != nil {
		return err
	}

	rules := []rule.Rule{
		&sharedv1r11.Rule242376{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242377{Logger: r.Logger().With("rule", v1r11.ID242377), Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242378{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242379{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242380{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242381{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242382{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242383{},
		&v1r11.Rule242384{},
		&v1r11.Rule242385{},
		&sharedv1r11.Rule242386{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242387{
			Logger:                  r.Logger().With("rule", v1r11.ID242387),
			InstanceID:              r.instanceID,
			ClusterClient:           shootClient,
			ClusterCoreV1RESTClient: shootClientSet.CoreV1().RESTClient(),
			ControlPlaneClient:      seedClient,
			ClusterPodContext:       shootPodContext,
			ControlPlaneNamespace:   r.shootNamespace,
		},
		&sharedv1r11.Rule242388{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242389{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242390{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242391{
			Logger:                  r.Logger().With("rule", v1r11.ID242391),
			InstanceID:              r.instanceID,
			ClusterClient:           shootClient,
			ClusterCoreV1RESTClient: shootClientSet.CoreV1().RESTClient(),
			ControlPlaneClient:      seedClient,
			ClusterPodContext:       shootPodContext,
			ControlPlaneNamespace:   r.shootNamespace,
		},
		&v1r11.Rule242392{
			Logger:                  r.Logger().With("rule", v1r11.ID242392),
			InstanceID:              r.instanceID,
			ClusterClient:           shootClient,
			ClusterCoreV1RESTClient: shootClientSet.CoreV1().RESTClient(),
			ControlPlaneClient:      seedClient,
			ClusterPodContext:       shootPodContext,
			ControlPlaneNamespace:   r.shootNamespace,
		},
		&v1r11.Rule242393{Logger: r.Logger().With("rule", v1r11.ID242393), InstanceID: r.instanceID, ClusterPodContext: shootPodContext},
		&v1r11.Rule242394{Logger: r.Logger().With("rule", v1r11.ID242394), InstanceID: r.instanceID, ClusterPodContext: shootPodContext},
		&v1r11.Rule242395{Logger: r.Logger().With("rule", v1r11.ID242395), Client: shootClient},
		&v1r11.Rule242396{},
		&v1r11.Rule242397{
			Logger:                  r.Logger().With("rule", v1r11.ID242397),
			InstanceID:              r.instanceID,
			ClusterClient:           shootClient,
			ClusterCoreV1RESTClient: shootClientSet.CoreV1().RESTClient(),
			ControlPlaneClient:      seedClient,
			ClusterPodContext:       shootPodContext,
			ControlPlaneNamespace:   r.shootNamespace,
		},
		&v1r11.Rule242398{},
		&v1r11.Rule242399{
			Logger:                  r.Logger().With("rule", v1r11.ID242399),
			InstanceID:              r.instanceID,
			ClusterClient:           shootClient,
			ClusterVersion:          semverShootKubernetesVersion,
			ClusterCoreV1RESTClient: shootClientSet.CoreV1().RESTClient(),
			ControlPlaneClient:      seedClient,
			ClusterPodContext:       shootPodContext,
			ControlPlaneNamespace:   r.shootNamespace,
		},
		&sharedv1r11.Rule242400{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242402{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242403{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242404{
			Logger:                r.Logger().With("rule", v1r11.ID242404),
			InstanceID:            r.instanceID,
			ClusterClient:         shootClient,
			ControlPlaneClient:    seedClient,
			ClusterPodContext:     shootPodContext,
			ControlPlaneNamespace: r.shootNamespace,
		},
		&v1r11.Rule242405{},
		&v1r11.Rule242406{},
		&v1r11.Rule242407{},
		&v1r11.Rule242408{},
		&sharedv1r11.Rule242409{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242410{},
		&v1r11.Rule242411{},
		&v1r11.Rule242412{},
		&v1r11.Rule242413{},
		&v1r11.Rule242414{
			Logger:                r.Logger().With("rule", v1r11.ID242414),
			ClusterClient:         shootClient,
			ControlPlaneClient:    seedClient,
			ControlPlaneNamespace: r.shootNamespace,
			Options:               opts242414,
		},
		&v1r11.Rule242415{
			Logger:                r.Logger().With("rule", v1r11.ID242415),
			ClusterClient:         shootClient,
			ControlPlaneClient:    seedClient,
			ControlPlaneNamespace: r.shootNamespace,
			Options:               opts242415,
		},
		&v1r11.Rule242417{Logger: r.Logger().With("rule", v1r11.ID242417), Client: shootClient},
		&sharedv1r11.Rule242418{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242419{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242420{
			Logger:                  r.Logger().With("rule", v1r11.ID242420),
			InstanceID:              r.instanceID,
			ClusterClient:           shootClient,
			ClusterCoreV1RESTClient: shootClientSet.CoreV1().RESTClient(),
			ControlPlaneClient:      seedClient,
			ClusterPodContext:       shootPodContext,
			ControlPlaneNamespace:   r.shootNamespace,
		},
		&sharedv1r11.Rule242421{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242422{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242423{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242424{
			Logger:                  r.Logger().With("rule", v1r11.ID242424),
			InstanceID:              r.instanceID,
			ClusterClient:           shootClient,
			ClusterCoreV1RESTClient: shootClientSet.CoreV1().RESTClient(),
			ControlPlaneClient:      seedClient,
			ClusterPodContext:       shootPodContext,
			ControlPlaneNamespace:   r.shootNamespace,
		},
		&v1r11.Rule242425{
			Logger:                  r.Logger().With("rule", v1r11.ID242425),
			InstanceID:              r.instanceID,
			ClusterClient:           shootClient,
			ClusterCoreV1RESTClient: shootClientSet.CoreV1().RESTClient(),
			ControlPlaneClient:      seedClient,
			ClusterPodContext:       shootPodContext,
			ControlPlaneNamespace:   r.shootNamespace,
		},
		&sharedv1r11.Rule242426{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242427{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242428{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242429{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242430{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242431{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242432{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242433{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242434{
			Logger:                  r.Logger().With("rule", v1r11.ID242434),
			InstanceID:              r.instanceID,
			ClusterClient:           shootClient,
			ClusterCoreV1RESTClient: shootClientSet.CoreV1().RESTClient(),
			ControlPlaneClient:      seedClient,
			ClusterPodContext:       shootPodContext,
			ControlPlaneNamespace:   r.shootNamespace,
		},
		&sharedv1r11.Rule242436{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242437{
			Logger:                r.Logger().With("rule", v1r11.ID242437),
			ClusterClient:         shootClient,
			ClusterVersion:        semverShootKubernetesVersion,
			ControlPlaneClient:    seedClient,
			ControlPlaneVersion:   semverSeedKubernetesVersion,
			ControlPlaneNamespace: r.shootNamespace,
		},
		&sharedv1r11.Rule242438{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242442{Logger: r.Logger().With("rule", v1r11.ID242442), ClusterClient: shootClient, ControlPlaneClient: seedClient, ControlPlaneNamespace: r.shootNamespace},
		&v1r11.Rule242443{},
		&v1r11.Rule242444{},
		&v1r11.Rule242445{},
		&v1r11.Rule242446{},
		&v1r11.Rule242447{},
		&v1r11.Rule242448{},
		&v1r11.Rule242449{},
		&v1r11.Rule242450{},
		&v1r11.Rule242451{},
		&v1r11.Rule242452{},
		&v1r11.Rule242453{},
		&v1r11.Rule242454{},
		&v1r11.Rule242455{},
		&v1r11.Rule242456{},
		&v1r11.Rule242457{},
		&v1r11.Rule242459{},
		&v1r11.Rule242460{},
		&sharedv1r11.Rule242461{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242462{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242463{Logger: r.Logger().With("rule", v1r11.ID242463), Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242464{Logger: r.Logger().With("rule", v1r11.ID242464), Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242465{},
		&v1r11.Rule242466{},
		&v1r11.Rule242467{},
		&v1r11.Rule245541{
			Logger:                  r.Logger().With("rule", v1r11.ID245541),
			InstanceID:              r.instanceID,
			ClusterClient:           shootClient,
			ClusterCoreV1RESTClient: shootClientSet.CoreV1().RESTClient(),
			ControlPlaneClient:      seedClient,
			ClusterPodContext:       shootPodContext,
			ControlPlaneNamespace:   r.shootNamespace,
		},
		&v1r11.Rule245542{Logger: r.Logger().With("rule", v1r11.ID245542), Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule245543{Logger: r.Logger().With("rule", v1r11.ID245543), Client: seedClient, Namespace: r.shootNamespace, Options: opts245543},
		&v1r11.Rule245544{Logger: r.Logger().With("rule", v1r11.ID245544), Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule254800{Logger: r.Logger().With("rule", v1r11.ID254800), Client: seedClient, Namespace: r.shootNamespace, Options: opts254800},
		&v1r11.Rule254801{
			Logger:                  r.Logger().With("rule", v1r11.ID254801),
			InstanceID:              r.instanceID,
			ClusterClient:           shootClient,
			ClusterVersion:          semverShootKubernetesVersion,
			ClusterCoreV1RESTClient: shootClientSet.CoreV1().RESTClient(),
			ControlPlaneClient:      seedClient,
			ClusterPodContext:       shootPodContext,
			ControlPlaneNamespace:   r.shootNamespace,
		},
		&v1r11.RuleNodeFiles{
			Logger:                r.Logger().With("rule", v1r11.IDNodeFiles),
			InstanceID:            r.instanceID,
			ClusterClient:         shootClient,
			ControlPlaneClient:    seedClient,
			ControlPlaneNamespace: r.shootNamespace,
			ClusterPodContext:     shootPodContext,
		},
		&v1r11.RulePodFiles{
			Logger:                 r.Logger().With("rule", v1r11.IDPodFiles),
			InstanceID:             r.instanceID,
			ClusterClient:          shootClient,
			ControlPlaneClient:     seedClient,
			ControlPlanePodContext: seedPodContext,
			ClusterPodContext:      shootPodContext,
			ControlPlaneNamespace:  r.shootNamespace,
			Options:                optsPodFiles,
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
