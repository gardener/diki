// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
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

func (r *Ruleset) registerV2R3Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
	runtimeClient, err := client.New(r.RuntimeConfig, client.Options{})
	if err != nil {
		return err
	}

	runtimePodContext, err := pod.NewSimplePodContext(runtimeClient, r.RuntimeConfig, r.AdditionalOpsPodLabels)
	if err != nil {
		return err
	}
	opts242445, err := getV2R3OptionOrNil[option.FileOwnerOptions](ruleOptions[sharedrules.ID242445].Args)
	if err != nil {
		return fmt.Errorf("rule option 242445 error: %s", err.Error())
	}
	opts242446, err := getV2R3OptionOrNil[option.FileOwnerOptions](ruleOptions[sharedrules.ID242446].Args)
	if err != nil {
		return fmt.Errorf("rule option 242446 error: %s", err.Error())
	}
	opts242451, err := getV2R3OptionOrNil[option.FileOwnerOptions](ruleOptions[sharedrules.ID242451].Args)
	if err != nil {
		return fmt.Errorf("rule option 242451 error: %s", err.Error())
	}
	opts245543, err := getV2R3OptionOrNil[sharedrules.Options245543](ruleOptions[sharedrules.ID245543].Args)
	if err != nil {
		return fmt.Errorf("rule option 245543 error: %s", err.Error())
	}

	rcFileChecks := retry.RetryConditionFromRegex(
		*retryerrors.ContainerNotFoundOnNodeRegexp,
		*retryerrors.ContainerFileNotFoundOnNodeRegexp,
		*retryerrors.ContainerNotReadyRegexp,
		*retryerrors.OpsPodNotFoundRegexp,
		*retryerrors.ObjectNotFoundRegexp,
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
			"The Kubernetes Scheduler must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.",
			"The Virtual Garden cluster does not make use of a Kubernetes Scheduler.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
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
			Client:             runtimeClient,
			Namespace:          ns,
			DeploymentName:     apiserverDeploymentName,
			ContainerName:      apiserverContainerName,
			ExpectedStartModes: []string{"RBAC", "Webhook"},
		},
		rule.NewSkipRule(
			sharedrules.ID242383,
			"User-managed resources must be created in dedicated namespaces.",
			"By design the Garden cluster provides separate namespaces for user projects and users do not have access to system namespaces.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			sharedrules.ID242384,
			"The Kubernetes Scheduler must have secure binding.",
			"The Virtual Garden cluster does not make use of a Kubernetes Scheduler.",
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
		&sharedrules.Rule242386{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		rule.NewSkipRule(
			sharedrules.ID242387,
			"The Kubernetes Kubelet must have the read-only port flag disabled.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
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
			"The Kubernetes Kubelet must have anonymous authentication disabled.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			sharedrules.ID242392,
			"The Kubernetes kubelet must enable explicit authorization.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			sharedrules.ID242393,
			"Kubernetes Worker Nodes must not have sshd service running.",
			"The Virtual Garden cluster does not have any nodes.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242394,
			"Kubernetes Worker Nodes must not have the sshd service enabled.",
			"The Virtual Garden cluster does not have any nodes.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242395,
			"Kubernetes dashboard must not be enabled.",
			"The Virtual Garden cluster does not have any nodes therefore it does not deploy a Kubernetes dashboard.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242396,
			"Kubernetes Kubectl cp command must give expected access and results.",
			"The Virtual Garden cluster does not have any nodes therefore it does not install kubectl.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242397,
			"Kubernetes kubelet static PodPath must not enable static pods.",
			"The Virtual Garden cluster does not have any nodes therefore there are no kubelets to check.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			// feature-gates.DynamicAuditing removed in v1.19. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
			sharedrules.ID242398,
			"Kubernetes DynamicAuditing must not be enabled.",
			"Option feature-gates.DynamicAuditing was removed in Kubernetes v1.19.",
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
			"Kubernetes Kubelet must deny hostname override.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242405,
			"Kubernetes manifests must be owned by root.",
			"Gardener does not deploy any control plane component as systemd processes or static pod.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242406,
			"Kubernetes kubelet configuration file must be owned by root.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242407,
			"The Kubernetes KubeletConfiguration files must have file permissions set to 644 or more restrictive.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242408,
			"The Kubernetes manifest files must have least privileges.",
			"Gardener does not deploy any control plane component as systemd processes or static pod.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		&sharedrules.Rule242409{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: kcmDeploymentName,
			ContainerName:  kcmContainerName,
		},
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
			"The Virtual Garden cluster does not make use of a Kubernetes Scheduler.",
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
		rule.NewSkipRule(
			sharedrules.ID242414,
			"The Kubernetes cluster must use non-privileged host ports for user pods.",
			noPodsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242415,
			"Secrets in Kubernetes must not be stored as environment variables.",
			noPodsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			sharedrules.ID242417,
			"Kubernetes must separate user functionality.",
			noPodsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
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
			"Kubernetes Kubelet must have the SSL Certificate Authority set.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
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
			"Kubernetes Kubelet must enable tlsPrivateKeyFile for client authentication to secure service.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242425,
			"Kubernetes Kubelet must enable tlsCertFile for client authentication to secure service.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
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
			"Kubernetes Kubelet must enable kernel protection.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		&sharedrules.Rule242436{
			Client:         runtimeClient,
			Namespace:      ns,
			DeploymentName: apiserverDeploymentName,
			ContainerName:  apiserverContainerName,
		},
		rule.NewSkipRule(
			sharedrules.ID242437,
			"Kubernetes must have a pod security policy set.",
			"PSPs are removed in K8s version 1.25.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
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
			"Kubernetes must contain the latest updates as authorized by IAVMs, CTOs, DTMs, and STIGs.",
			"Scanning/patching security vulnerabilities should be enforced organizationally. Security vulnerability scanning should be automated and maintainers should be informed automatically.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242444,
			"Kubernetes component manifests must be owned by root.",
			"Rule is duplicate of 242405. Gardener does not deploy any control plane component as systemd processes or static pod.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242445)),
			retry.WithBaseRule(&sharedrules.Rule242445{
				Logger:                r.Logger().With("rule_id", sharedrules.ID242445),
				InstanceID:            r.instanceID,
				Client:                runtimeClient,
				Namespace:             ns,
				PodContext:            runtimePodContext,
				ETCDMainOldSelector:   labels.SelectorFromSet(labels.Set{"instance": etcdMain}),
				ETCDMainSelector:      labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": etcdMain}),
				ETCDEventsOldSelector: labels.SelectorFromSet(labels.Set{"instance": etcdEvents}),
				ETCDEventsSelector:    labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": etcdEvents}),
				Options:               opts242445,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242446)),
			retry.WithBaseRule(&sharedrules.Rule242446{
				Logger:          r.Logger().With("rule_id", sharedrules.ID242446),
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
			"The Kubernetes Kube Proxy kubeconfig must have file permissions set to 644 or more restrictive.",
			noPodsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242448,
			"The Kubernetes Kube Proxy kubeconfig must be owned by root.",
			noPodsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242449,
			"The Kubernetes Kubelet certificate authority file must have file permissions set to 644 or more restrictive.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242450,
			"The Kubernetes Kubelet certificate authority must be owned by root.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242451)),
			retry.WithBaseRule(&rules.Rule242451{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242451),
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
			"The Kubernetes kubelet KubeConfig must have file permissions set to 644 or more restrictive.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242453,
			"The Kubernetes kubelet KubeConfig file must be owned by root.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242454,
			"The Kubernetes kubeadm.conf must be owned by root.",
			`Gardener does not use kubeadm and also does not store any "main config" anywhere (flow/component logic built-in/in-code).`,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242455,
			"The Kubernetes kubeadm.conf must have file permissions set to 644 or more restrictive.",
			`Gardener does not use kubeadm and also does not store any "main config" anywhere (flow/component logic built-in/in-code).`,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242456,
			"The Kubernetes kubelet config must have file permissions set to 644 or more restrictive.",
			"Duplicate of 242452. "+noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242457,
			"The Kubernetes kubelet config must be owned by root.",
			"Duplicate of 242453. "+noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242459)),
			retry.WithBaseRule(&sharedrules.Rule242459{
				Logger:                r.Logger().With("rule_id", sharedrules.ID242459),
				InstanceID:            r.instanceID,
				Client:                runtimeClient,
				Namespace:             ns,
				PodContext:            runtimePodContext,
				ETCDMainOldSelector:   labels.SelectorFromSet(labels.Set{"instance": etcdMain}),
				ETCDMainSelector:      labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": etcdMain}),
				ETCDEventsOldSelector: labels.SelectorFromSet(labels.Set{"instance": etcdEvents}),
				ETCDEventsSelector:    labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": etcdEvents}),
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242460)),
			retry.WithBaseRule(&sharedrules.Rule242460{
				Logger:          r.Logger().With("rule_id", sharedrules.ID242460),
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
			"The Kubernetes API Server audit log path must be set.",
			"Rule is duplicate of 242402.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242466)),
			retry.WithBaseRule(&rules.Rule242466{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242466),
				InstanceID: r.instanceID,
				Client:     runtimeClient,
				Namespace:  ns,
				PodContext: runtimePodContext,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242467)),
			retry.WithBaseRule(&rules.Rule242467{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242467),
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
			"Kubernetes Kubelet must not disable timeouts.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
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
			"Kubernetes endpoints must use approved organizational certificate and key pair to protect information in transit.",
			noKubeletsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			sharedrules.ID254800,
			"Kubernetes must have a Pod Security Admission control file configured.",
			noPodsMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			sharedrules.ID254801,
			"Kubernetes must enable PodSecurity admission controller on static pods and Kubelets.",
			noKubeletsMsg,
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

func parseV2R3Options[O rules.RuleOption](options any) (*O, error) {
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

func getV2R3OptionOrNil[O rules.RuleOption](options any) (*O, error) {
	if options == nil {
		return nil, nil
	}
	return parseV2R3Options[O](options)
}
