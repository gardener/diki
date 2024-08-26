// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	"github.com/gardener/diki/pkg/provider/virtualgarden/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/rule/retry"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/retryerrors"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

func (r *Ruleset) registerV2R1Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
	runtimeClient, err := client.New(r.RuntimeConfig, client.Options{})
	if err != nil {
		return err
	}

	runtimePodContext, err := pod.NewSimplePodContext(runtimeClient, r.RuntimeConfig, r.AdditionalOpsPodLabels)
	if err != nil {
		return err
	}
	opts242445, err := getV2R1OptionOrNil[option.FileOwnerOptions](ruleOptions[sharedrules.ID242445].Args)
	if err != nil {
		return fmt.Errorf("rule option 242445 error: %s", err.Error())
	}
	opts242446, err := getV2R1OptionOrNil[option.FileOwnerOptions](ruleOptions[sharedrules.ID242446].Args)
	if err != nil {
		return fmt.Errorf("rule option 242446 error: %s", err.Error())
	}
	opts242451, err := getV2R1OptionOrNil[option.FileOwnerOptions](ruleOptions[sharedrules.ID242451].Args)
	if err != nil {
		return fmt.Errorf("rule option 242451 error: %s", err.Error())
	}
	opts245543, err := getV2R1OptionOrNil[sharedrules.Options245543](ruleOptions[sharedrules.ID245543].Args)
	if err != nil {
		return fmt.Errorf("rule option 245543 error: %s", err.Error())
	}

	rcFileChecks := retry.RetryConditionFromRegex(
		*retryerrors.ContainerNotFoundOnNodeRegexp,
		*retryerrors.ContainerFileNotFoundOnNodeRegexp,
		*retryerrors.ContainerNotReadyRegexp,
		*retryerrors.OpsPodNotFoundRegexp,
	)

	const (
		ns                      = "garden"
		etcdMain                = "virtual-garden-etcd-main"
		etcdEvents              = "virtual-garden-etcd-events"
		kcmDeploymentName       = "virtual-garden-kube-controller-manager"
		kcmContainerName        = "kube-controller-manager"
		apiserverDeploymentName = "virtual-garden-kube-apiserver"
		apiserverContainerName  = "kube-apiserver"
		noKubeletsMsg           = "The Virtual Garden cluster does not have any nodes therefore there are no kubelets to check."
		noPodsMsg               = "The Virtual Garden cluster does not have any nodes therefore there cluster does not have any pods."
	)
	rules := []rule.Rule{
		&sharedrules.Rule242376{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: kcmDeploymentName,
			ContainerName:  kcmContainerName,
		},
		rule.NewSkipRule(
			sharedrules.ID242377,
			"The Kubernetes Scheduler must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination (MEDIUM 242377)",
			"The Virtual Garden cluster does not make use of a Kubernetes Scheduler.",
			rule.Skipped,
		),
		&sharedrules.Rule242378{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&sharedrules.Rule242379{
			Client:                runtimeClient,
			Namespace:             ns,
			StatefulSetETCDMain:   etcdMain,
			StatefulSetETCDEvents: etcdEvents,
		},
		&sharedrules.Rule242380{
			Client:                runtimeClient,
			Namespace:             ns,
			StatefulSetETCDMain:   etcdMain,
			StatefulSetETCDEvents: etcdEvents,
		},
		&sharedrules.Rule242381{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: kcmDeploymentName,
			ContainerName:  kcmContainerName,
		},
		&sharedrules.Rule242382{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
			ExpectedModes:  []string{"RBAC", "Webhook"},
		},
		rule.NewSkipRule(
			sharedrules.ID242383,
			"User-managed resources must be created in dedicated namespaces (HIGH 242383)",
			"By design the Garden cluster provides separate namespaces for user projects and users do not have access to system namespaces.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242384,
			"The Kubernetes Scheduler must have secure binding (MEDIUM 242384)",
			"The Virtual Garden cluster does not make use of a Kubernetes Scheduler.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242385,
			"The Kubernetes Controller Manager must have secure binding (MEDIUM 242385)",
			"The Kubernetes Controller Manager runs in a container which already has limited access to network interfaces. In addition ingress traffic to the Kubernetes Controller Manager is restricted via network policies, making an unintended exposure less likely.",
			rule.Skipped,
		),
		&sharedrules.Rule242386{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		rule.NewSkipRule(
			sharedrules.ID242387,
			"The Kubernetes Kubelet must have the read-only port flag disabled (HIGH 242387)",
			noKubeletsMsg,
			rule.Skipped,
		),
		&sharedrules.Rule242388{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&sharedrules.Rule242389{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&sharedrules.Rule242390{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		rule.NewSkipRule(
			sharedrules.ID242391,
			"The Kubernetes Kubelet must have anonymous authentication disabled (HIGH 242391)",
			noKubeletsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242392,
			"The Kubernetes kubelet must enable explicit authorization (HIGH 242392)",
			noKubeletsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242393,
			"Kubernetes Worker Nodes must not have sshd service running (MEDIUM 242393)",
			"The Virtual Garden cluster does not have any nodes.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242394,
			"Kubernetes Worker Nodes must not have the sshd service enabled (MEDIUM 242394)",
			"The Virtual Garden cluster does not have any nodes.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242395,
			"Kubernetes dashboard must not be enabled (MEDIUM 242395)",
			"The Virtual Garden cluster does not have any nodes therefore it does not deploy a Kubernetes dashboard.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242396,
			"Kubernetes Kubectl cp command must give expected access and results (MEDIUM 242396)",
			"The Virtual Garden cluster does not have any nodes therefore it does not install kubectl.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242397,
			"Kubernetes kubelet static PodPath must not enable static pods (HIGH 242397)",
			"The Virtual Garden cluster does not have any nodes therefore there are no kubelets to check.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			// feature-gates.DynamicAuditing removed in v1.19. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
			sharedrules.ID242398,
			"Kubernetes DynamicAuditing must not be enabled (MEDIUM 242398)",
			"Option feature-gates.DynamicAuditing was removed in Kubernetes v1.19.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242399,
			"Kubernetes DynamicKubeletConfig must not be enabled (MEDIUM 242399)",
			noKubeletsMsg,
			rule.Skipped,
		),
		&rules.Rule242400{
			Client:    runtimeClient,
			Namespace: ns,
		},
		&sharedrules.Rule242402{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&sharedrules.Rule242403{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
		},
		rule.NewSkipRule(
			sharedrules.ID242404,
			"Kubernetes Kubelet must deny hostname override (MEDIUM 242404)",
			noKubeletsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242405,
			"Kubernetes manifests must be owned by root (MEDIUM 242405)",
			"Gardener does not deploy any control plane component as systemd processes or static pod.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242406,
			"Kubernetes kubelet configuration file must be owned by root (MEDIUM 242406)",
			noKubeletsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242407,
			"The Kubernetes KubeletConfiguration files must have file permissions set to 644 or more restrictive (MEDIUM 242407)",
			noKubeletsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242408,
			"The Kubernetes manifest files must have least privileges (MEDIUM 242408)",
			"Gardener does not deploy any control plane component as systemd processes or static pod.",
			rule.Skipped,
		),
		&sharedrules.Rule242409{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: kcmDeploymentName,
			ContainerName:  kcmContainerName,
		},
		rule.NewSkipRule(
			sharedrules.ID242410,
			"The Kubernetes API Server must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) (MEDIUM 242410)",
			"Cannot be tested and should be enforced organizationally. Gardener uses a minimum of known and automatically opened/used/created ports/protocols/services (PPSM stands for Ports, Protocols, Service Management).",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242411,
			"The Kubernetes Scheduler must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) (MEDIUM 242411)",
			"The Virtual Garden cluster does not make use of a Kubernetes Scheduler.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242412,
			"The Kubernetes Controllers must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) (MEDIUM 242412)",
			"Cannot be tested and should be enforced organizationally. Gardener uses a minimum of known and automatically opened/used/created ports/protocols/services (PPSM stands for Ports, Protocols, Service Management).",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242413,
			"The Kubernetes etcd must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) (MEDIUM 242413)",
			"Cannot be tested and should be enforced organizationally. Gardener uses a minimum of known and automatically opened/used/created ports/protocols/services (PPSM stands for Ports, Protocols, Service Management).",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242414,
			"The Kubernetes cluster must use non-privileged host ports for user pods (MEDIUM 242414)",
			noPodsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242415,
			"Secrets in Kubernetes must not be stored as environment variables (HIGH 242415)",
			noPodsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242417,
			"Kubernetes must separate user functionality (MEDIUM 242417)",
			noPodsMsg,
			rule.Skipped,
		),
		&sharedrules.Rule242418{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&sharedrules.Rule242419{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		rule.NewSkipRule(
			sharedrules.ID242420,
			"Kubernetes Kubelet must have the SSL Certificate Authority set (MEDIUM 242420)",
			noKubeletsMsg,
			rule.Skipped,
		),
		&sharedrules.Rule242421{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: kcmDeploymentName,
			ContainerName:  kcmContainerName,
		},
		&sharedrules.Rule242422{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&sharedrules.Rule242423{
			Client:                runtimeClient,
			Namespace:             ns,
			StatefulSetETCDMain:   etcdMain,
			StatefulSetETCDEvents: etcdEvents,
		},
		rule.NewSkipRule(
			sharedrules.ID242424,
			"Kubernetes Kubelet must enable tlsPrivateKeyFile for client authentication to secure service (MEDIUM 242424)",
			noKubeletsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242425,
			"Kubernetes Kubelet must enable tlsCertFile for client authentication to secure service (MEDIUM 242425)",
			noKubeletsMsg,
			rule.Skipped,
		),
		&sharedrules.Rule242426{
			Client:                runtimeClient,
			Namespace:             ns,
			StatefulSetETCDMain:   etcdMain,
			StatefulSetETCDEvents: etcdEvents,
		},
		&sharedrules.Rule242427{
			Client:                runtimeClient,
			Namespace:             ns,
			StatefulSetETCDMain:   etcdMain,
			StatefulSetETCDEvents: etcdEvents,
		},
		&sharedrules.Rule242428{
			Client:                runtimeClient,
			Namespace:             ns,
			StatefulSetETCDMain:   etcdMain,
			StatefulSetETCDEvents: etcdEvents,
		},
		&sharedrules.Rule242429{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&sharedrules.Rule242430{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&sharedrules.Rule242431{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&sharedrules.Rule242432{
			Client:                runtimeClient,
			Namespace:             ns,
			StatefulSetETCDMain:   etcdMain,
			StatefulSetETCDEvents: etcdEvents,
		},
		&sharedrules.Rule242433{
			Client:                runtimeClient,
			Namespace:             ns,
			StatefulSetETCDMain:   etcdMain,
			StatefulSetETCDEvents: etcdEvents,
		},
		rule.NewSkipRule(
			sharedrules.ID242434,
			"Kubernetes Kubelet must enable kernel protection (HIGH 242434)",
			noKubeletsMsg,
			rule.Skipped,
		),
		&sharedrules.Rule242436{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		rule.NewSkipRule(
			sharedrules.ID242437,
			"Kubernetes must have a pod security policy set (HIGH 242437)",
			"PSPs are removed in K8s version 1.25.",
			rule.Skipped,
		),
		&sharedrules.Rule242438{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&rules.Rule242442{
			Client:    runtimeClient,
			Namespace: ns,
		},
		rule.NewSkipRule(
			sharedrules.ID242443,
			"Kubernetes must contain the latest updates as authorized by IAVMs, CTOs, DTMs, and STIGs (MEDIUM 242443)",
			"Scanning/patching security vulnerabilities should be enforced organizationally. Security vulnerability scanning should be automated and maintainers should be informed automatically.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242444,
			"Kubernetes component manifests must be owned by root (MEDIUM 242444)",
			"Rule is duplicate of 242405. Gardener does not deploy any control plane component as systemd processes or static pod.",
			rule.Skipped,
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule", sharedrules.ID242445)),
			retry.WithBaseRule(&sharedrules.Rule242445{
				Logger:             r.Logger().With("rule", sharedrules.ID242445),
				InstanceID:         r.instanceID,
				Client:             runtimeClient,
				Namespace:          ns,
				PodContext:         runtimePodContext,
				ETCDMainSelector:   labels.SelectorFromSet(labels.Set{"instance": etcdMain}),
				ETCDEventsSelector: labels.SelectorFromSet(labels.Set{"instance": etcdEvents}),
				Options:            opts242445,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule", sharedrules.ID242446)),
			retry.WithBaseRule(&sharedrules.Rule242446{
				Logger:          r.Logger().With("rule", sharedrules.ID242446),
				InstanceID:      r.instanceID,
				Client:          runtimeClient,
				Namespace:       ns,
				PodContext:      runtimePodContext,
				DeploymentNames: []string{apiserverDeploymentName, kcmDeploymentName},
				Options:         opts242446,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		rule.NewSkipRule(
			sharedrules.ID242447,
			"The Kubernetes Kube Proxy kubeconfig must have file permissions set to 644 or more restrictive (MEDIUM 242447)",
			noPodsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242448,
			"The Kubernetes Kube Proxy kubeconfig must be owned by root (MEDIUM 242448)",
			noPodsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242449,
			"The Kubernetes Kubelet certificate authority file must have file permissions set to 644 or more restrictive (MEDIUM 242449)",
			noKubeletsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242450,
			"The Kubernetes Kubelet certificate authority must be owned by root (MEDIUM 242450)",
			noKubeletsMsg,
			rule.Skipped,
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule", sharedrules.ID242451)),
			retry.WithBaseRule(&rules.Rule242451{
				Logger:     r.Logger().With("rule", sharedrules.ID242451),
				InstanceID: r.instanceID,
				Client:     runtimeClient,
				Namespace:  ns,
				PodContext: runtimePodContext,
				Options:    opts242451,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		rule.NewSkipRule(
			sharedrules.ID242452,
			"The Kubernetes kubelet KubeConfig must have file permissions set to 644 or more restrictive (MEDIUM 242452)",
			noKubeletsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242453,
			"The Kubernetes kubelet KubeConfig file must be owned by root (MEDIUM 242453)",
			noKubeletsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242454,
			"The Kubernetes kubeadm.conf must be owned by root (MEDIUM 242454)",
			`Gardener does not use kubeadm and also does not store any "main config" anywhere (flow/component logic built-in/in-code).`,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242455,
			"The Kubernetes kubeadm.conf must have file permissions set to 644 or more restrictive (MEDIUM 242455)",
			`Gardener does not use kubeadm and also does not store any "main config" anywhere (flow/component logic built-in/in-code).`,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242456,
			"The Kubernetes kubelet config must have file permissions set to 644 or more restrictive (MEDIUM 242456)",
			"Duplicate of 242452. "+noKubeletsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID242457,
			"The Kubernetes kubelet config must be owned by root (MEDIUM 242457)",
			"Duplicate of 242453. "+noKubeletsMsg,
			rule.Skipped,
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule", sharedrules.ID242459)),
			retry.WithBaseRule(&sharedrules.Rule242459{
				Logger:             r.Logger().With("rule", sharedrules.ID242459),
				InstanceID:         r.instanceID,
				Client:             runtimeClient,
				Namespace:          ns,
				PodContext:         runtimePodContext,
				ETCDMainSelector:   labels.SelectorFromSet(labels.Set{"instance": etcdMain}),
				ETCDEventsSelector: labels.SelectorFromSet(labels.Set{"instance": etcdEvents}),
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule", sharedrules.ID242460)),
			retry.WithBaseRule(&sharedrules.Rule242460{
				Logger:          r.Logger().With("rule", sharedrules.ID242460),
				InstanceID:      r.instanceID,
				Client:          runtimeClient,
				Namespace:       ns,
				PodContext:      runtimePodContext,
				DeploymentNames: []string{apiserverDeploymentName, kcmDeploymentName},
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		&sharedrules.Rule242461{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&sharedrules.Rule242462{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&sharedrules.Rule242463{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&sharedrules.Rule242464{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		rule.NewSkipRule(
			sharedrules.ID242465,
			"The Kubernetes API Server audit log path must be set (MEDIUM 242465)",
			"Rule is duplicate of 242402.",
			rule.Skipped,
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule", sharedrules.ID242466)),
			retry.WithBaseRule(&rules.Rule242466{
				Logger:     r.Logger().With("rule", sharedrules.ID242466),
				InstanceID: r.instanceID,
				Client:     runtimeClient,
				Namespace:  ns,
				PodContext: runtimePodContext,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule", sharedrules.ID242467)),
			retry.WithBaseRule(&rules.Rule242467{
				Logger:     r.Logger().With("rule", sharedrules.ID242467),
				InstanceID: r.instanceID,
				Client:     runtimeClient,
				Namespace:  ns,
				PodContext: runtimePodContext,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		rule.NewSkipRule(
			sharedrules.ID245541,
			"Kubernetes Kubelet must not disable timeouts (MEDIUM 245541)",
			noKubeletsMsg,
			rule.Skipped,
		),
		&sharedrules.Rule245542{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		&sharedrules.Rule245543{
			Client:         runtimeClient,
			Namespace:      ns,
			Options:        opts245543,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		rule.NewSkipRule(
			sharedrules.ID245544,
			"Kubernetes endpoints must use approved organizational certificate and key pair to protect information in transit (HIGH 245544)",
			noKubeletsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID254800,
			"Kubernetes must have a Pod Security Admission control file configured (HIGH 254800)",
			noPodsMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedrules.ID254801,
			"Kubernetes must enable PodSecurity admission controller on static pods and Kubelets (HIGH 254801)",
			noKubeletsMsg,
			rule.Skipped,
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
	if len(rules) != 91 {
		return fmt.Errorf("revision expects 91 registered rules, but got: %d", len(rules))
	}

	return r.AddRules(rules...)
}

func parseV2R1Options[O rules.RuleOption](options any) (*O, error) {
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

func getV2R1OptionOrNil[O rules.RuleOption](options any) (*O, error) {
	if options == nil {
		return nil, nil
	}
	return parseV2R1Options[O](options)
}
