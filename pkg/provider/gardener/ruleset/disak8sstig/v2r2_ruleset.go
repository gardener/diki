// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"encoding/json"
	"fmt"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	kubernetesgardener "github.com/gardener/gardener/pkg/client/kubernetes"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/rule/retry"
	option "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/retryerrors"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

func parseV2R2Options[O rules.RuleOption](options any) (*O, error) {
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

func getV2R2OptionOrNil[O rules.RuleOption](options any) (*O, error) {
	if options == nil {
		return nil, nil
	}
	return parseV2R2Options[O](options)
}

func (r *Ruleset) registerV2R2Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
	shootClient, err := client.New(r.ShootConfig, client.Options{Scheme: kubernetesgardener.ShootScheme})
	if err != nil {
		return err
	}

	seedClient, err := client.New(r.SeedConfig, client.Options{Scheme: kubernetesgardener.SeedScheme})
	if err != nil {
		return err
	}

	shootPodContext, err := pod.NewSimplePodContext(shootClient, r.ShootConfig, r.AdditionalOpsPodLabels)
	if err != nil {
		return err
	}

	seedPodContext, err := pod.NewSimplePodContext(seedClient, r.SeedConfig, r.AdditionalOpsPodLabels)
	if err != nil {
		return err
	}

	shootClientSet, err := kubernetes.NewForConfig(r.ShootConfig)
	if err != nil {
		return err
	}

	opts242400, err := getV2R2OptionOrNil[option.KubeProxyOptions](ruleOptions[sharedrules.ID242400].Args)
	if err != nil {
		return fmt.Errorf("rule option 242400 error: %s", err.Error())
	}
	opts242414, err := getV2R2OptionOrNil[option.Options242414](ruleOptions[sharedrules.ID242414].Args)
	if err != nil {
		return fmt.Errorf("rule option 242414 error: %s", err.Error())
	}
	opts242415, err := getV2R2OptionOrNil[option.Options242415](ruleOptions[sharedrules.ID242415].Args)
	if err != nil {
		return fmt.Errorf("rule option 242415 error: %s", err.Error())
	}
	opts242445, err := getV2R2OptionOrNil[option.FileOwnerOptions](ruleOptions[sharedrules.ID242445].Args)
	if err != nil {
		return fmt.Errorf("rule option 242445 error: %s", err.Error())
	}
	opts242446, err := getV2R2OptionOrNil[option.FileOwnerOptions](ruleOptions[sharedrules.ID242446].Args)
	if err != nil {
		return fmt.Errorf("rule option 242446 error: %s", err.Error())
	}
	opts242451, err := getV2R2OptionOrNil[rules.Options242451](ruleOptions[sharedrules.ID242451].Args)
	if err != nil {
		return fmt.Errorf("rule option 242451 error: %s", err.Error())
	}
	opts242466, err := getV2R2OptionOrNil[option.KubeProxyOptions](ruleOptions[sharedrules.ID242466].Args)
	if err != nil {
		return fmt.Errorf("rule option 242466 error: %s", err.Error())
	}
	opts242467, err := getV2R2OptionOrNil[option.KubeProxyOptions](ruleOptions[sharedrules.ID242467].Args)
	if err != nil {
		return fmt.Errorf("rule option 242467 error: %s", err.Error())
	}
	opts245543, err := getV2R2OptionOrNil[sharedrules.Options245543](ruleOptions[sharedrules.ID245543].Args)
	if err != nil {
		return fmt.Errorf("rule option 245543 error: %s", err.Error())
	}
	opts254800, err := getV2R2OptionOrNil[sharedrules.Options254800](ruleOptions[sharedrules.ID254800].Args)
	if err != nil {
		return fmt.Errorf("rule option 254800 error: %s", err.Error())
	}

	rcOpsPod := retry.RetryConditionFromRegex(
		*retryerrors.OpsPodNotFoundRegexp,
	)
	rcFileChecks := retry.RetryConditionFromRegex(
		*retryerrors.ContainerNotFoundOnNodeRegexp,
		*retryerrors.ContainerFileNotFoundOnNodeRegexp,
		*retryerrors.ContainerNotReadyRegexp,
		*retryerrors.OpsPodNotFoundRegexp,
		*retryerrors.ObjectNotFoundRegexp,
	)

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
		&sharedrules.Rule242376{Client: seedClient, Namespace: r.shootNamespace},
		&rules.Rule242377{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242378{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242379{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242380{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242381{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242382{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242383{Client: shootClient},
		rule.NewSkipRule(
			sharedrules.ID242384,
			"The Kubernetes Scheduler must have secure binding.",
			"The Kubernetes Scheduler runs in a container which already has limited access to network interfaces. In addition ingress traffic to the Kubernetes Scheduler is restricted via network policies, making an unintended exposure less likely.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242385,
			"The Kubernetes Controller Manager must have secure binding.",
			"The Kubernetes Controller Manager runs in a container which already has limited access to network interfaces. In addition ingress traffic to the Kubernetes Controller Manager is restricted via network policies, making an unintended exposure less likely.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		&sharedrules.Rule242386{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242387{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedrules.Rule242388{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242389{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242390{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242391{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedrules.Rule242392{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242393)),
			retry.WithBaseRule(&sharedrules.Rule242393{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242393),
				InstanceID: r.instanceID,
				Client:     shootClient,
				PodContext: shootPodContext,
				Options: &sharedrules.Options242393{
					NodeGroupByLabels: workerPoolGroupByLabels,
				},
			}),
			retry.WithRetryCondition(rcOpsPod),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242394)),
			retry.WithBaseRule(&sharedrules.Rule242394{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242394),
				InstanceID: r.instanceID,
				Client:     shootClient,
				PodContext: shootPodContext,
				Options: &sharedrules.Options242394{
					NodeGroupByLabels: workerPoolGroupByLabels,
				},
			}),
			retry.WithRetryCondition(rcOpsPod),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		&sharedrules.Rule242395{Client: shootClient},
		rule.NewSkipRule(
			sharedrules.ID242396,
			"Kubernetes Kubectl cp command must give expected access and results.",
			`"kubectl" is not installed into control plane pods or worker nodes and Gardener does not offer Kubernetes v1.12 or older.`,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		&sharedrules.Rule242397{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		rule.NewSkipRule(
			sharedrules.ID242398,
			"Kubernetes DynamicAuditing must not be enabled.",
			// feature-gates.DynamicAuditing removed in v1.19. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
			"Option feature-gates.DynamicAuditing removed in Kubernetes v1.19.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242399,
			"Kubernetes DynamicKubeletConfig must not be enabled.",
			// feature-gates.DynamicKubeletConfig removed in v1.26. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
			"Option feature-gates.DynamicKubeletConfig removed in Kubernetes v1.26.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242400)),
			retry.WithBaseRule(&rules.Rule242400{
				Logger:                r.Logger().With("rule_id", sharedrules.ID242400),
				InstanceID:            r.instanceID,
				ControlPlaneClient:    seedClient,
				ClusterClient:         shootClient,
				ClusterPodContext:     shootPodContext,
				ClusterV1RESTClient:   shootClientSet.CoreV1().RESTClient(),
				ControlPlaneNamespace: r.shootNamespace,
				Options:               opts242400,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		&sharedrules.Rule242402{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242403{Client: seedClient, Namespace: r.shootNamespace},
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242404)),
			retry.WithBaseRule(&sharedrules.Rule242404{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242404),
				InstanceID: r.instanceID,
				Client:     shootClient,
				PodContext: shootPodContext,
				Options: &sharedrules.Options242404{
					NodeGroupByLabels: workerPoolGroupByLabels,
				},
			}),
			retry.WithRetryCondition(rcOpsPod),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		rule.NewSkipRule(
			sharedrules.ID242405,
			"Kubernetes manifests must be owned by root.",
			"Gardener does not deploy any control plane component as systemd processes or static pod.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242406)),
			retry.WithBaseRule(&sharedrules.Rule242406{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242406),
				InstanceID: r.instanceID,
				Client:     shootClient,
				PodContext: shootPodContext,
				Options: &sharedrules.Options242406{
					NodeGroupByLabels: workerPoolGroupByLabels,
					FileOwnerOptions:  gardenerFileOwnerOptions,
				},
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242407)),
			retry.WithBaseRule(&sharedrules.Rule242407{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242407),
				InstanceID: r.instanceID,
				Client:     shootClient,
				PodContext: shootPodContext,
				Options: &sharedrules.Options242407{
					NodeGroupByLabels: workerPoolGroupByLabels,
				},
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		rule.NewSkipRule(
			sharedrules.ID242408,
			"The Kubernetes manifest files must have least privileges.",
			`Gardener does not deploy any control plane component as systemd processes or static pod.`,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		&sharedrules.Rule242409{Client: seedClient, Namespace: r.shootNamespace},
		rule.NewSkipRule(
			sharedrules.ID242410,
			"The Kubernetes API Server must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).",
			"Cannot be tested and should be enforced organizationally. Gardener uses a minimum of known and automatically opened/used/created ports/protocols/services (PPSM stands for Ports, Protocols, Service Management).",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242411,
			"The Kubernetes Scheduler must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).",
			"Cannot be tested and should be enforced organizationally. Gardener uses a minimum of known and automatically opened/used/created ports/protocols/services (PPSM stands for Ports, Protocols, Service Management).",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242412,
			"The Kubernetes Controllers must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).",
			"Cannot be tested and should be enforced organizationally. Gardener uses a minimum of known and automatically opened/used/created ports/protocols/services (PPSM stands for Ports, Protocols, Service Management).",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242413,
			"The Kubernetes etcd must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).",
			"Cannot be tested and should be enforced organizationally. Gardener uses a minimum of known and automatically opened/used/created ports/protocols/services (PPSM stands for Ports, Protocols, Service Management).",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		&rules.Rule242414{
			ClusterClient:         shootClient,
			ControlPlaneClient:    seedClient,
			ControlPlaneNamespace: r.shootNamespace,
			Options:               opts242414,
		},
		&rules.Rule242415{
			ClusterClient:         shootClient,
			ControlPlaneClient:    seedClient,
			ControlPlaneNamespace: r.shootNamespace,
			Options:               opts242415,
		},
		&sharedrules.Rule242417{
			Client: shootClient,
			Options: &sharedrules.Options242417{
				AcceptedPods: []sharedrules.AcceptedPods242417{
					{
						PodSelector: option.PodSelector{
							PodMatchLabels: map[string]string{
								resourcesv1alpha1.ManagedBy: "gardener",
							},
							NamespaceMatchLabels: map[string]string{
								"kubernetes.io/metadata.name": "kube-system",
							},
						},
						Justification: "Gardener managed pods are not user pods",
						Status:        "Passed",
					},
				},
			},
		},
		&sharedrules.Rule242418{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242419{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242420{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedrules.Rule242421{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242422{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242423{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242424{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedrules.Rule242425{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedrules.Rule242426{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242427{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242428{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242429{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242430{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242431{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242432{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242433{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242434{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedrules.Rule242436{Client: seedClient, Namespace: r.shootNamespace},
		rule.NewSkipRule(
			sharedrules.ID242437,
			"Kubernetes must have a pod security policy set.",
			"PSPs are removed in K8s version 1.25.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		&sharedrules.Rule242438{Client: seedClient, Namespace: r.shootNamespace},
		&rules.Rule242442{ClusterClient: shootClient, ControlPlaneClient: seedClient, ControlPlaneNamespace: r.shootNamespace},
		rule.NewSkipRule(
			sharedrules.ID242443,
			"Kubernetes must contain the latest updates as authorized by IAVMs, CTOs, DTMs, and STIGs.",
			"Scanning/patching security vulnerabilities should be enforced organizationally. Security vulnerability scanning should be automated and maintainers should be informed automatically.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242444,
			"Kubernetes component manifests must be owned by root.",
			`Rule is duplicate of "242405"`,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242445)),
			retry.WithBaseRule(&sharedrules.Rule242445{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242445),
				InstanceID: r.instanceID,
				Client:     seedClient,
				PodContext: seedPodContext,
				Namespace:  r.shootNamespace,
				Options:    opts242445,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242446)),
			retry.WithBaseRule(&sharedrules.Rule242446{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242446),
				InstanceID: r.instanceID,
				Client:     seedClient,
				PodContext: seedPodContext,
				Namespace:  r.shootNamespace,
				Options:    opts242446,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242447)),
			retry.WithBaseRule(&sharedrules.Rule242447{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242447),
				InstanceID: r.instanceID,
				Client:     shootClient,
				PodContext: shootPodContext,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242448)),
			retry.WithBaseRule(&sharedrules.Rule242448{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242448),
				InstanceID: r.instanceID,
				Client:     shootClient,
				PodContext: shootPodContext,
				Options: &sharedrules.Options242448{
					FileOwnerOptions: gardenerFileOwnerOptions,
				},
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242449)),
			retry.WithBaseRule(&sharedrules.Rule242449{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242449),
				InstanceID: r.instanceID,
				Client:     shootClient,
				PodContext: shootPodContext,
				Options: &sharedrules.Options242449{
					NodeGroupByLabels: workerPoolGroupByLabels,
				},
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242450)),
			retry.WithBaseRule(&sharedrules.Rule242450{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242450),
				InstanceID: r.instanceID,
				Client:     shootClient,
				PodContext: shootPodContext,
				Options: &sharedrules.Options242450{
					NodeGroupByLabels: workerPoolGroupByLabels,
					FileOwnerOptions:  gardenerFileOwnerOptions,
				},
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242451)),
			retry.WithBaseRule(&rules.Rule242451{
				Logger:                 r.Logger().With("rule_id", sharedrules.ID242451),
				InstanceID:             r.instanceID,
				ControlPlaneClient:     seedClient,
				ClusterClient:          shootClient,
				ControlPlanePodContext: seedPodContext,
				ClusterPodContext:      shootPodContext,
				ControlPlaneNamespace:  r.shootNamespace,
				Options:                opts242451,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242452)),
			retry.WithBaseRule(&sharedrules.Rule242452{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242452),
				InstanceID: r.instanceID,
				Client:     shootClient,
				PodContext: shootPodContext,
				Options: &sharedrules.Options242452{
					NodeGroupByLabels: workerPoolGroupByLabels,
				},
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242453)),
			retry.WithBaseRule(&sharedrules.Rule242453{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242453),
				InstanceID: r.instanceID,
				Client:     shootClient,
				PodContext: shootPodContext,
				Options: &sharedrules.Options242453{
					NodeGroupByLabels: workerPoolGroupByLabels,
					FileOwnerOptions:  gardenerFileOwnerOptions,
				},
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		rule.NewSkipRule(
			sharedrules.ID242454,
			"Kubernetes kubeadm.conf must be owned by root.",
			`Gardener does not use "kubeadm" and also does not store any "main config" anywhere in seed or shoot (flow/component logic built-in/in-code).`,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242455,
			"Kubernetes kubeadm.conf must have file permissions set to 644 or more restrictive.",
			`Gardener does not use "kubeadm" and also does not store any "main config" anywhere in seed or shoot (flow/component logic built-in/in-code).`,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242456,
			"Kubernetes kubelet config must have file permissions set to 644 or more restrictive.",
			`Rule is duplicate of "242452".`,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242457,
			"Kubernetes kubelet config must be owned by root.",
			`Rule is duplicate of "242453".`,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242459)),
			retry.WithBaseRule(&sharedrules.Rule242459{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242459),
				InstanceID: r.instanceID,
				Client:     seedClient,
				PodContext: seedPodContext,
				Namespace:  r.shootNamespace,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242460)),
			retry.WithBaseRule(&sharedrules.Rule242460{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242460),
				InstanceID: r.instanceID,
				Client:     seedClient,
				PodContext: seedPodContext,
				Namespace:  r.shootNamespace,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		&sharedrules.Rule242461{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242462{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242463{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule242464{Client: seedClient, Namespace: r.shootNamespace},
		rule.NewSkipRule(
			sharedrules.ID242465,
			"Kubernetes API Server audit log path must be set.",
			`Rule is duplicate of "242402"`,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242466)),
			retry.WithBaseRule(&rules.Rule242466{
				Logger:                 r.Logger().With("rule_id", sharedrules.ID242466),
				InstanceID:             r.instanceID,
				ControlPlaneClient:     seedClient,
				ClusterClient:          shootClient,
				ControlPlanePodContext: seedPodContext,
				ClusterPodContext:      shootPodContext,
				ControlPlaneNamespace:  r.shootNamespace,
				Options:                opts242466,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242467)),
			retry.WithBaseRule(&rules.Rule242467{
				Logger:                 r.Logger().With("rule_id", sharedrules.ID242467),
				InstanceID:             r.instanceID,
				ControlPlaneClient:     seedClient,
				ClusterClient:          shootClient,
				ControlPlanePodContext: seedPodContext,
				ClusterPodContext:      shootPodContext,
				ControlPlaneNamespace:  r.shootNamespace,
				Options:                opts242467,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		&sharedrules.Rule245541{
			Client:       shootClient,
			V1RESTClient: shootClientSet.CoreV1().RESTClient(),
		},
		&sharedrules.Rule245542{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule245543{Client: seedClient, Namespace: r.shootNamespace, Options: opts245543},
		&sharedrules.Rule245544{Client: seedClient, Namespace: r.shootNamespace},
		&sharedrules.Rule254800{Client: seedClient, Namespace: r.shootNamespace, Options: opts254800},
		rule.NewSkipRule(
			// featureGates.PodSecurity made GA in v1.25 and removed in v1.28. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
			sharedrules.ID254801,
			"Kubernetes must enable PodSecurity admission controller on static pods and Kubelets.",
			"Option featureGates.PodSecurity was made GA in v1.25 and removed in v1.28.",
			rule.Skipped,
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
	if len(rules) != 91 {
		return fmt.Errorf("revision expects 91 registered rules, but got: %d", len(rules))
	}

	return r.AddRules(rules...)
}
