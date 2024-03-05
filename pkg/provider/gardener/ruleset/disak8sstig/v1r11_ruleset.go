// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"encoding/json"

	"github.com/Masterminds/semver/v3"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	kubernetesgardener "github.com/gardener/gardener/pkg/client/kubernetes"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
	option "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

func parseV1R11Options[O v1r11.RuleOption](options any) (*O, error) {
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

func getV1R11OptionOrNil[O v1r11.RuleOption](options any) (*O, error) {
	if options == nil {
		return nil, nil
	}
	return parseV1R11Options[O](options)
}

func (r *Ruleset) registerV1R11Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
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

	opts242414, err := getV1R11OptionOrNil[v1r11.Options242414](ruleOptions[sharedv1r11.ID242414].Args)
	if err != nil {
		return err
	}
	opts242415, err := getV1R11OptionOrNil[v1r11.Options242415](ruleOptions[sharedv1r11.ID242415].Args)
	if err != nil {
		return err
	}
	opts242445, err := getV1R11OptionOrNil[option.FileOwnerOptions](ruleOptions[sharedv1r11.ID242445].Args)
	if err != nil {
		return err
	}
	opts242446, err := getV1R11OptionOrNil[option.FileOwnerOptions](ruleOptions[sharedv1r11.ID242446].Args)
	if err != nil {
		return err
	}
	opts245543, err := getV1R11OptionOrNil[sharedv1r11.Options245543](ruleOptions[sharedv1r11.ID245543].Args)
	if err != nil {
		return err
	}
	opts242451, err := getV1R11OptionOrNil[option.FileOwnerOptions](ruleOptions[sharedv1r11.ID242451].Args)
	if err != nil {
		return err
	}
	opts254800, err := getV1R11OptionOrNil[sharedv1r11.Options254800](ruleOptions[sharedv1r11.ID254800].Args)
	if err != nil {
		return err
	}

	// Gardener images use distroless nonroot user with ID 65532
	// https://github.com/GoogleContainerTools/distroless/blob/main/base/base.bzl#L8
	gardenerFileOwnerOptions := &option.FileOwnerOptions{
		ExpectedFileOwner: option.ExpectedOwner{
			Users:  []string{"0", "65532"},
			Groups: []string{"0", "65532"},
		},
	}
	workerPoolGroupByLabels := []string{"worker.gardener.cloud/pool"}

	rules := []rule.Rule{
		&sharedv1r11.Rule242376{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242377{Logger: r.Logger().With("rule", sharedv1r11.ID242377), Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242378{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242379{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242380{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242381{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242382{Client: seedClient, Namespace: r.shootNamespace},
		rule.NewSkipRule(
			sharedv1r11.ID242383,
			"User-managed resources must be created in dedicated namespaces (HIGH 242383)",
			"By definition, all resources that Gardener creates are no end-user resources.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242384,
			"The Kubernetes Scheduler must have secure binding (MEDIUM 242384)",
			"The Kubernetes Scheduler runs in a container which already has limited access to network interfaces. In addition ingress traffic to the Kubernetes Scheduler is restricted via network policies, making an unintended exposure less likely.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242385,
			"The Kubernetes Controller Manager must have secure binding (MEDIUM 242385)",
			"The Kubernetes Controller Manager runs in a container which already has limited access to network interfaces. In addition ingress traffic to the Kubernetes Controller Manager is restricted via network policies, making an unintended exposure less likely.",
			rule.Skipped,
		),
		&sharedv1r11.Rule242386{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242387{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedv1r11.Rule242388{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242389{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242390{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242391{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedv1r11.Rule242392{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedv1r11.Rule242393{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242393),
			InstanceID: r.instanceID,
			Client:     shootClient,
			PodContext: shootPodContext,
			Options: &sharedv1r11.Options242393{
				GroupByLabels: workerPoolGroupByLabels,
			},
		},
		&sharedv1r11.Rule242394{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242394),
			InstanceID: r.instanceID,
			Client:     shootClient,
			PodContext: shootPodContext,
			Options: &sharedv1r11.Options242394{
				GroupByLabels: workerPoolGroupByLabels,
			},
		},
		&sharedv1r11.Rule242395{Client: shootClient},
		rule.NewSkipRule(
			sharedv1r11.ID242396,
			"Kubernetes Kubectl cp command must give expected access and results (MEDIUM 242396)",
			`"kubectl" is not installed into control plane pods or worker nodes and Gardener does not offer Kubernetes v1.12 or older.`,
			rule.Skipped,
		),
		&sharedv1r11.Rule242397{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		rule.NewSkipRule(
			sharedv1r11.ID242398,
			"Kubernetes DynamicAuditing must not be enabled (MEDIUM 242398)",
			// feature-gates.DynamicAuditing removed in v1.19. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
			"Option feature-gates.DynamicAuditing removed in Kubernetes v1.19.",
			rule.Skipped,
		),
		&sharedv1r11.Rule242399{
			Client:            shootClient,
			KubernetesVersion: semverShootKubernetesVersion,
			V1RESTClient:      shootClientSet.CoreV1().RESTClient(),
		},
		&v1r11.Rule242400{
			Logger:                r.Logger().With("rule", sharedv1r11.ID242400),
			InstanceID:            r.instanceID,
			ControlPlaneClient:    seedClient,
			ClusterClient:         shootClient,
			ClusterPodContext:     shootPodContext,
			ClusterV1RESTClient:   shootClientSet.CoreV1().RESTClient(),
			ControlPlaneNamespace: r.shootNamespace,
		},
		&sharedv1r11.Rule242402{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242403{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242404{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242404),
			InstanceID: r.instanceID,
			Client:     shootClient,
			PodContext: shootPodContext,
			Options: &sharedv1r11.Options242404{
				GroupByLabels: workerPoolGroupByLabels,
			},
		},
		rule.NewSkipRule(
			sharedv1r11.ID242405,
			"Kubernetes manifests must be owned by root (MEDIUM 242405)",
			"Gardener does not deploy any control plane component as systemd processes or static pod.",
			rule.Skipped,
		),
		&sharedv1r11.Rule242406{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242406),
			InstanceID: r.instanceID,
			Client:     shootClient,
			PodContext: shootPodContext,
			Options: &sharedv1r11.Options242406{
				GroupByLabels:    workerPoolGroupByLabels,
				FileOwnerOptions: gardenerFileOwnerOptions,
			},
		},
		&sharedv1r11.Rule242407{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242407),
			InstanceID: r.instanceID,
			Client:     shootClient,
			PodContext: shootPodContext,
			Options: &sharedv1r11.Options242407{
				GroupByLabels: workerPoolGroupByLabels,
			},
		},
		rule.NewSkipRule(
			sharedv1r11.ID242408,
			"The Kubernetes manifest files must have least privileges  (MEDIUM 242408)",
			`Gardener does not deploy any control plane component as systemd processes or static pod.`,
			rule.Skipped,
		),
		&sharedv1r11.Rule242409{Client: seedClient, Namespace: r.shootNamespace},
		rule.NewSkipRule(
			sharedv1r11.ID242410,
			"The Kubernetes API Server must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) (MEDIUM 242410)",
			"Cannot be tested and should be enforced organizationally. Gardener uses a minimum of known and automatically opened/used/created ports/protocols/services (PPSM stands for Ports, Protocols, Service Management).",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242411,
			"The Kubernetes Scheduler must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) (MEDIUM 242411)",
			"Cannot be tested and should be enforced organizationally. Gardener uses a minimum of known and automatically opened/used/created ports/protocols/services (PPSM stands for Ports, Protocols, Service Management).",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242412,
			"The Kubernetes Controllers must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) (MEDIUM 242412)",
			"Cannot be tested and should be enforced organizationally. Gardener uses a minimum of known and automatically opened/used/created ports/protocols/services (PPSM stands for Ports, Protocols, Service Management).",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242413,
			"The Kubernetes etcd must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) (MEDIUM 242413)",
			"Cannot be tested and should be enforced organizationally. Gardener uses a minimum of known and automatically opened/used/created ports/protocols/services (PPSM stands for Ports, Protocols, Service Management).",
			rule.Skipped,
		),
		&v1r11.Rule242414{
			Logger:                r.Logger().With("rule", sharedv1r11.ID242414),
			ClusterClient:         shootClient,
			ControlPlaneClient:    seedClient,
			ControlPlaneNamespace: r.shootNamespace,
			Options:               opts242414,
		},
		&v1r11.Rule242415{
			Logger:                r.Logger().With("rule", sharedv1r11.ID242415),
			ClusterClient:         shootClient,
			ControlPlaneClient:    seedClient,
			ControlPlaneNamespace: r.shootNamespace,
			Options:               opts242415,
		},
		&sharedv1r11.Rule242417{
			Client: shootClient,
			Options: &sharedv1r11.Options242417{
				AcceptedPods: []sharedv1r11.AcceptedPods242417{
					{
						PodMatchLabels: map[string]string{
							resourcesv1alpha1.ManagedBy: "gardener",
						},
						Justification: "Gardener managed pods are not user pods",
						Status:        "Passed",
					},
				},
			},
		},
		&sharedv1r11.Rule242418{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242419{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242420{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedv1r11.Rule242421{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242422{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242423{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242424{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedv1r11.Rule242425{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedv1r11.Rule242426{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242427{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242428{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242429{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242430{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242431{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242432{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242433{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242434{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedv1r11.Rule242436{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242437{
			Logger:                r.Logger().With("rule", sharedv1r11.ID242437),
			ClusterClient:         shootClient,
			ClusterVersion:        semverShootKubernetesVersion,
			ControlPlaneClient:    seedClient,
			ControlPlaneVersion:   semverSeedKubernetesVersion,
			ControlPlaneNamespace: r.shootNamespace,
		},
		&sharedv1r11.Rule242438{Client: seedClient, Namespace: r.shootNamespace},
		&v1r11.Rule242442{Logger: r.Logger().With("rule", sharedv1r11.ID242442), ClusterClient: shootClient, ControlPlaneClient: seedClient, ControlPlaneNamespace: r.shootNamespace},
		rule.NewSkipRule(
			sharedv1r11.ID242443,
			"Kubernetes must contain the latest updates as authorized by IAVMs, CTOs, DTMs, and STIGs (MEDIUM 242443)",
			"Scanning/patching security vulnerabilities should be enforced organizationally. Security vulnerability scanning should be automated and maintainers should be informed automatically.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242444,
			"Kubernetes component manifests must be owned by root (MEDIUM 242444)",
			`Rule is duplicate of "242405"`,
			rule.Skipped,
		),
		&sharedv1r11.Rule242445{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242445),
			InstanceID: r.instanceID,
			Client:     seedClient,
			PodContext: seedPodContext,
			Namespace:  r.shootNamespace,
			Options:    opts242445,
		},
		&sharedv1r11.Rule242446{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242446),
			InstanceID: r.instanceID,
			Client:     seedClient,
			PodContext: seedPodContext,
			Namespace:  r.shootNamespace,
			Options:    opts242446,
		},
		&sharedv1r11.Rule242447{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242447),
			InstanceID: r.instanceID,
			Client:     shootClient,
			PodContext: shootPodContext,
		},
		&sharedv1r11.Rule242448{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242448),
			InstanceID: r.instanceID,
			Client:     shootClient,
			PodContext: shootPodContext,
			Options: &sharedv1r11.Options242448{
				FileOwnerOptions: gardenerFileOwnerOptions,
			},
		},
		&sharedv1r11.Rule242449{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242449),
			InstanceID: r.instanceID,
			Client:     shootClient,
			PodContext: shootPodContext,
			Options: &sharedv1r11.Options242449{
				GroupByLabels: workerPoolGroupByLabels,
			},
		},
		&sharedv1r11.Rule242450{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242450),
			InstanceID: r.instanceID,
			Client:     shootClient,
			PodContext: shootPodContext,
			Options: &sharedv1r11.Options242450{
				GroupByLabels:    workerPoolGroupByLabels,
				FileOwnerOptions: gardenerFileOwnerOptions,
			},
		},
		&sharedv1r11.Rule242451{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242451),
			InstanceID: r.instanceID,
			Client:     seedClient,
			PodContext: seedPodContext,
			Namespace:  r.shootNamespace,
			Options:    opts242451,
		},
		&sharedv1r11.Rule242452{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242452),
			InstanceID: r.instanceID,
			Client:     seedClient,
			PodContext: seedPodContext,
			Options: &sharedv1r11.Options242452{
				GroupByLabels: workerPoolGroupByLabels,
			},
		},
		&sharedv1r11.Rule242453{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242453),
			InstanceID: r.instanceID,
			Client:     shootClient,
			PodContext: shootPodContext,
			Options: &sharedv1r11.Options242453{
				GroupByLabels:    workerPoolGroupByLabels,
				FileOwnerOptions: gardenerFileOwnerOptions,
			},
		},
		rule.NewSkipRule(
			sharedv1r11.ID242454,
			"Kubernetes kubeadm.conf must be owned by root(MEDIUM 242454)",
			`Gardener does not use "kubeadm" and also does not store any "main config" anywhere in seed or shoot (flow/component logic built-in/in-code).`,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242455,
			"Kubernetes kubeadm.conf must have file permissions set to 644 or more restrictive (MEDIUM 242455)",
			`Gardener does not use "kubeadm" and also does not store any "main config" anywhere in seed or shoot (flow/component logic built-in/in-code).`,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242456,
			"Kubernetes kubelet config must have file permissions set to 644 or more restrictive (MEDIUM 242456)",
			`Rule is duplicate of "242452".`,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242457,
			"Kubernetes kubelet config must be owned by root (MEDIUM 242457)",
			`Rule is duplicate of "242453".`,
			rule.Skipped,
		),
		&sharedv1r11.Rule242459{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242459),
			InstanceID: r.instanceID,
			Client:     seedClient,
			PodContext: seedPodContext,
			Namespace:  r.shootNamespace,
		},
		&sharedv1r11.Rule242460{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242460),
			InstanceID: r.instanceID,
			Client:     seedClient,
			PodContext: seedPodContext,
			Namespace:  r.shootNamespace,
		},
		&sharedv1r11.Rule242461{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242462{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242463{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule242464{Client: seedClient, Namespace: r.shootNamespace},
		rule.NewSkipRule(
			sharedv1r11.ID242465,
			"Kubernetes API Server audit log path must be set (MEDIUM 242465)",
			`Rule is duplicate of "242402"`,
			rule.Skipped,
		),
		&v1r11.Rule242466{
			Logger:                 r.Logger().With("rule", sharedv1r11.ID242466),
			InstanceID:             r.instanceID,
			ControlPlaneClient:     seedClient,
			ClusterClient:          shootClient,
			ControlPlanePodContext: seedPodContext,
			ClusterPodContext:      shootPodContext,
			ControlPlaneNamespace:  r.shootNamespace,
		},
		&sharedv1r11.Rule242467{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242467),
			InstanceID: r.instanceID,
			Client:     seedClient,
			PodContext: seedPodContext,
			Namespace:  r.shootNamespace,
		},
		&sharedv1r11.Rule245541{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedv1r11.Rule245542{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule245543{Client: seedClient, Namespace: r.shootNamespace, Options: opts245543},
		&sharedv1r11.Rule245544{Client: seedClient, Namespace: r.shootNamespace},
		&sharedv1r11.Rule254800{Client: seedClient, Namespace: r.shootNamespace, Options: opts254800},
		rule.NewSkipRule(
			// featureGates.PodSecurity made GA in v1.25 and removed in v1.28. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
			sharedv1r11.ID254801,
			"Kubernetes must enable PodSecurity admission controller on static pods and Kubelets (HIGH 254801)",
			"Option featureGates.PodSecurity was made GA in v1.25 and removed in v1.28.",
			rule.Skipped,
		),
		&v1r11.RuleNodeFiles{
			Logger:                r.Logger().With("rule", v1r11.IDNodeFiles),
			InstanceID:            r.instanceID,
			ClusterClient:         shootClient,
			ControlPlaneClient:    seedClient,
			ControlPlaneNamespace: r.shootNamespace,
			ClusterPodContext:     shootPodContext,
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
