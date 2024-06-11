// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"encoding/json"
	"fmt"

	"github.com/Masterminds/semver/v3"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

func (r *Ruleset) registerV1R11Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
	client, err := client.New(r.Config, client.Options{})
	if err != nil {
		return err
	}

	podContext, err := pod.NewSimplePodContext(client, r.Config, r.AdditionalOpsPodLabels)
	if err != nil {
		return err
	}

	clientSet, err := kubernetes.NewForConfig(r.Config)
	if err != nil {
		return err
	}

	kubernetesVersion, err := clientSet.Discovery().ServerVersion()
	if err != nil {
		return err
	}

	semverKubernetesVersion, err := semver.NewVersion(kubernetesVersion.String())
	if err != nil {
		return err
	}

	opts242383, err := getV1R11OptionOrNil[sharedv1r11.Options242383](ruleOptions[sharedv1r11.ID242383].Args)
	if err != nil {
		return fmt.Errorf("rule option 242383 error: %s", err.Error())
	}
	opts242393, err := getV1R11OptionOrNil[sharedv1r11.Options242393](ruleOptions[sharedv1r11.ID242393].Args)
	if err != nil {
		return fmt.Errorf("rule option 242393 error: %s", err.Error())
	}
	opts242394, err := getV1R11OptionOrNil[sharedv1r11.Options242394](ruleOptions[sharedv1r11.ID242394].Args)
	if err != nil {
		return fmt.Errorf("rule option 242394 error: %s", err.Error())
	}
	opts242396, err := getV1R11OptionOrNil[sharedv1r11.Options242396](ruleOptions[sharedv1r11.ID242396].Args)
	if err != nil {
		return fmt.Errorf("rule option 242396 error: %s", err.Error())
	}
	opts242400, err := getV1R11OptionOrNil[v1r11.Options242400](ruleOptions[sharedv1r11.ID242400].Args)
	if err != nil {
		return fmt.Errorf("rule option 242400 error: %s", err.Error())
	}
	opts242404, err := getV1R11OptionOrNil[sharedv1r11.Options242404](ruleOptions[sharedv1r11.ID242404].Args)
	if err != nil {
		return fmt.Errorf("rule option 242404 error: %s", err.Error())
	}
	opts242406, err := getV1R11OptionOrNil[sharedv1r11.Options242406](ruleOptions[sharedv1r11.ID242406].Args)
	if err != nil {
		return fmt.Errorf("rule option 242406 error: %s", err.Error())
	}
	opts242407, err := getV1R11OptionOrNil[sharedv1r11.Options242407](ruleOptions[sharedv1r11.ID242407].Args)
	if err != nil {
		return fmt.Errorf("rule option 242407 error: %s", err.Error())
	}
	opts242414, err := getV1R11OptionOrNil[option.Options242414](ruleOptions[sharedv1r11.ID242414].Args)
	if err != nil {
		return fmt.Errorf("rule option 242414 error: %s", err.Error())
	}
	opts242415, err := getV1R11OptionOrNil[option.Options242415](ruleOptions[sharedv1r11.ID242415].Args)
	if err != nil {
		return fmt.Errorf("rule option 242415 error: %s", err.Error())
	}
	opts242417, err := getV1R11OptionOrNil[sharedv1r11.Options242417](ruleOptions[sharedv1r11.ID242417].Args)
	if err != nil {
		return fmt.Errorf("rule option 242417 error: %s", err.Error())
	}
	opts242442, err := getV1R11OptionOrNil[v1r11.Options242442](ruleOptions[sharedv1r11.ID242442].Args)
	if err != nil {
		return fmt.Errorf("rule option 242442 error: %s", err.Error())
	}
	opts242447, err := getV1R11OptionOrNil[sharedv1r11.Options242447](ruleOptions[sharedv1r11.ID242447].Args)
	if err != nil {
		return fmt.Errorf("rule option 242447 error: %s", err.Error())
	}
	opts242448, err := getV1R11OptionOrNil[sharedv1r11.Options242448](ruleOptions[sharedv1r11.ID242448].Args)
	if err != nil {
		return fmt.Errorf("rule option 242448 error: %s", err.Error())
	}
	opts242449, err := getV1R11OptionOrNil[sharedv1r11.Options242449](ruleOptions[sharedv1r11.ID242449].Args)
	if err != nil {
		return fmt.Errorf("rule option 242449 error: %s", err.Error())
	}
	opts242450, err := getV1R11OptionOrNil[sharedv1r11.Options242450](ruleOptions[sharedv1r11.ID242450].Args)
	if err != nil {
		return fmt.Errorf("rule option 242450 error: %s", err.Error())
	}
	opts242451, err := getV1R11OptionOrNil[v1r11.Options242451](ruleOptions[sharedv1r11.ID242451].Args)
	if err != nil {
		return fmt.Errorf("rule option 242451 error: %s", err.Error())
	}
	opts242452, err := getV1R11OptionOrNil[sharedv1r11.Options242452](ruleOptions[sharedv1r11.ID242452].Args)
	if err != nil {
		return fmt.Errorf("rule option 242452 error: %s", err.Error())
	}
	opts242453, err := getV1R11OptionOrNil[sharedv1r11.Options242453](ruleOptions[sharedv1r11.ID242453].Args)
	if err != nil {
		return fmt.Errorf("rule option 242453 error: %s", err.Error())
	}
	opts242466, err := getV1R11OptionOrNil[v1r11.Options242466](ruleOptions[sharedv1r11.ID242466].Args)
	if err != nil {
		return fmt.Errorf("rule option 242466 error: %s", err.Error())
	}
	opts242467, err := getV1R11OptionOrNil[v1r11.Options242467](ruleOptions[sharedv1r11.ID242467].Args)
	if err != nil {
		return fmt.Errorf("rule option 242467 error: %s", err.Error())
	}

	const (
		noControlPlaneMsg = "The Managed Kubernetes cluster does not have access to control plane components."
	)
	rules := []rule.Rule{
		rule.NewSkipRule(
			sharedv1r11.ID242376,
			"The Kubernetes Controller Manager must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination (MEDIUM 242376)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242377,
			"The Kubernetes Scheduler must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination (MEDIUM 242377)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242378,
			"The Kubernetes API Server must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination (MEDIUM 242378)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242379,
			"The Kubernetes etcd must use TLS to protect the confidentiality of sensitive data during electronic dissemination (MEDIUM 242379)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242380,
			"The Kubernetes etcd must use TLS to protect the confidentiality of sensitive data during electronic dissemination (MEDIUM 242380)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242381,
			"The Kubernetes Controller Manager must create unique service accounts for each work payload (HIGH 242381)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242382,
			"The Kubernetes API Server must enable Node,RBAC as the authorization mode (MEDIUM 242382)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		&sharedv1r11.Rule242383{
			Client:  client,
			Options: opts242383,
		},
		rule.NewSkipRule(
			sharedv1r11.ID242384,
			"The Kubernetes Scheduler must have secure binding (MEDIUM 242384)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242385,
			"The Kubernetes Controller Manager must have secure binding (MEDIUM 242385)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242386,
			"The Kubernetes API server must have the insecure port flag disabled (HIGH 242386)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		&sharedv1r11.Rule242387{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		rule.NewSkipRule(
			sharedv1r11.ID242388,
			"The Kubernetes API server must have the insecure bind address not set (HIGH 242388)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242389,
			"The Kubernetes API server must have the secure port set (MEDIUM 242389)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242390,
			"The Kubernetes API server must have anonymous authentication disabled (HIGH 242390)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		&sharedv1r11.Rule242391{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		&sharedv1r11.Rule242392{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		&sharedv1r11.Rule242393{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242393),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242393,
		},
		&sharedv1r11.Rule242394{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242394),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242394,
		},
		&sharedv1r11.Rule242395{Client: client},
		&sharedv1r11.Rule242396{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242396),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242396,
		},
		&sharedv1r11.Rule242397{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		rule.NewSkipRule(
			// feature-gates.DynamicAuditing removed in v1.19. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
			sharedv1r11.ID242398,
			"Kubernetes DynamicAuditing must not be enabled (MEDIUM 242398)",
			"Option feature-gates.DynamicAuditing was removed in Kubernetes v1.19.",
			rule.Skipped,
		),
		&sharedv1r11.Rule242399{
			Client:            client,
			KubernetesVersion: semverKubernetesVersion,
			V1RESTClient:      clientSet.CoreV1().RESTClient(),
		},
		&v1r11.Rule242400{
			Logger:       r.Logger().With("rule", sharedv1r11.ID242400),
			InstanceID:   r.instanceID,
			Client:       client,
			PodContext:   podContext,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
			Options:      opts242400,
		},
		rule.NewSkipRule(
			sharedv1r11.ID242402,
			"The Kubernetes API Server must have an audit log path set (MEDIUM 242402)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242403,
			"Kubernetes API Server must generate audit records that identify what type of event has occurred, identify the source of the event, contain the event results, identify any users, and identify any containers associated with the event (MEDIUM 242403)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		&sharedv1r11.Rule242404{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242404),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242404,
		},
		rule.NewSkipRule(
			sharedv1r11.ID242405,
			"Kubernetes manifests must be owned by root (MEDIUM 242405)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		&sharedv1r11.Rule242406{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242406),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242406,
		},
		&sharedv1r11.Rule242407{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242407),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242407,
		},
		rule.NewSkipRule(
			sharedv1r11.ID242408,
			"The Kubernetes manifest files must have least privileges (MEDIUM 242408)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242409,
			"Kubernetes Controller Manager must disable profiling (MEDIUM 242409)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242410,
			"The Kubernetes API Server must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) (MEDIUM 242410)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242411,
			"The Kubernetes Scheduler must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) (MEDIUM 242411)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242412,
			"The Kubernetes Controllers must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) (MEDIUM 242412)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242413,
			"The Kubernetes etcd must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) (MEDIUM 242413)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		&v1r11.Rule242414{
			Client:  client,
			Options: opts242414,
		},
		&v1r11.Rule242415{
			Client:  client,
			Options: opts242415,
		},
		&sharedv1r11.Rule242417{
			Client:  client,
			Options: opts242417,
		},
		rule.NewSkipRule(
			sharedv1r11.ID242418,
			"The Kubernetes API server must use approved cipher suites (MEDIUM 242418)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242419,
			"Kubernetes API Server must have the SSL Certificate Authority set (MEDIUM 242419)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		&sharedv1r11.Rule242420{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		rule.NewSkipRule(
			sharedv1r11.ID242421,
			"Kubernetes Controller Manager must have the SSL Certificate Authority set (MEDIUM 242421)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242422,
			"Kubernetes API Server must have a certificate for communication (MEDIUM 242422)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242423,
			"Kubernetes etcd must enable client authentication to secure service (MEDIUM 242423)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		&sharedv1r11.Rule242424{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		&sharedv1r11.Rule242425{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		rule.NewSkipRule(
			sharedv1r11.ID242426,
			"Kubernetes etcd must enable client authentication to secure service (MEDIUM 242426)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242427,
			"Kubernetes etcd must have a key file for secure communication (MEDIUM 242427)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242428,
			"Kubernetes etcd must have a certificate for communication (MEDIUM 242428)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242429,
			"Kubernetes etcd must have the SSL Certificate Authority set (MEDIUM 242429)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242430,
			"Kubernetes etcd must have a certificate for communication (MEDIUM 242430)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242431,
			"Kubernetes etcd must have a key file for secure communication (MEDIUM 242431)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242432,
			"Kubernetes etcd must have peer-cert-file set for secure communication (MEDIUM 242432)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242433,
			"Kubernetes etcd must have a peer-key-file set for secure communication (MEDIUM 242433)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		&sharedv1r11.Rule242434{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		rule.NewSkipRule(
			sharedv1r11.ID242436,
			"The Kubernetes API server must have the ValidatingAdmissionWebhook enabled (HIGH 242436)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242437,
			"Kubernetes must have a pod security policy set (HIGH 242437)",
			"PSPs are removed in K8s version 1.25.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242438,
			"Kubernetes API Server must configure timeouts to limit attack surface (MEDIUM 242438)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		&v1r11.Rule242442{
			// We check only system (kube-proxy) pods in this rule, since there can be a user case to run different versions of images.
			Client:  client,
			Options: opts242442,
		},
		rule.NewSkipRule(
			sharedv1r11.ID242443,
			"Kubernetes must contain the latest updates as authorized by IAVMs, CTOs, DTMs, and STIGs (MEDIUM 242443)",
			"Scanning/patching security vulnerabilities should be enforced organizationally. Security vulnerability scanning should be automated and maintainers should be informed automatically.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242444,
			"Kubernetes component manifests must be owned by root (MEDIUM 242444)",
			"Rule is duplicate of 242405. "+noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242445,
			"The Kubernetes component etcd must be owned by etcd (MEDIUM 242445)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242446,
			"The Kubernetes conf files must be owned by root (MEDIUM 242446)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		&sharedv1r11.Rule242447{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242447),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242447,
		},
		&sharedv1r11.Rule242448{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242448),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242448,
		},
		&sharedv1r11.Rule242449{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242449),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242449,
		},
		&sharedv1r11.Rule242450{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242450),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242450,
		},
		&v1r11.Rule242451{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242451),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242451,
		},
		&sharedv1r11.Rule242452{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242452),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242452,
		},
		&sharedv1r11.Rule242453{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242453),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242453,
		},
		rule.NewSkipRule(
			sharedv1r11.ID242454,
			"The Kubernetes kubeadm.conf must be owned by root (MEDIUM 242454)",
			`Gardener does not use kubeadm and also does not store any "main config" anywhere (flow/component logic built-in/in-code).`,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242455,
			"The Kubernetes kubeadm.conf must have file permissions set to 644 or more restrictive (MEDIUM 242455)",
			`Gardener does not use kubeadm and also does not store any "main config" anywhere (flow/component logic built-in/in-code).`,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242456,
			"The Kubernetes kubelet config must have file permissions set to 644 or more restrictive (MEDIUM 242456)",
			"Duplicate of 242452.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242457,
			"The Kubernetes kubelet config must be owned by root (MEDIUM 242457)",
			"Duplicate of 242453.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242459,
			"The Kubernetes etcd must have file permissions set to 644 or more restrictive (MEDIUM 242459)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242460,
			"The Kubernetes admin kubeconfig must have file permissions set to 644 or more restrictive (MEDIUM 242460)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242461,
			"Kubernetes API Server audit logs must be enabled (MEDIUM 242461)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242462,
			"The Kubernetes API Server must be set to audit log max size (MEDIUM 242462)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242463,
			"The Kubernetes API Server must be set to audit log maximum backup (MEDIUM 242463)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242464,
			"The Kubernetes API Server audit log retention must be set (MEDIUM 242464)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242465,
			"The Kubernetes API Server audit log path must be set (MEDIUM 242465)",
			"Duplicate of 242402. "+noControlPlaneMsg,
			rule.Skipped,
		),
		&v1r11.Rule242466{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242466),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242466,
		},
		&v1r11.Rule242467{
			Logger:     r.Logger().With("rule", sharedv1r11.ID242467),
			InstanceID: r.instanceID,
			Client:     client,
			PodContext: podContext,
			Options:    opts242467,
		},
		&sharedv1r11.Rule245541{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		rule.NewSkipRule(
			sharedv1r11.ID245542,
			"Kubernetes API Server must disable basic authentication to protect information in transit (HIGH 245542)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID245543,
			"Kubernetes API Server must disable token authentication to protect information in transit (HIGH 245543)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID245544,
			"Kubernetes endpoints must use approved organizational certificate and key pair to protect information in transit (HIGH 245544)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID254800,
			"Kubernetes must have a Pod Security Admission control file configured (HIGH 254800)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			// featureGates.PodSecurity made GA in v1.25 and removed in v1.28. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
			sharedv1r11.ID254801,
			"Kubernetes must enable PodSecurity admission controller on static pods and Kubelets (HIGH 254801)",
			"Option featureGates.PodSecurity was made GA in v1.25 and removed in v1.28.",
			rule.Skipped,
		),
	}

	for i, r := range rules {
		opt, found := ruleOptions[r.ID()]
		if found && opt.Skip != nil && opt.Skip.Enabled {
			rules[i] = rule.NewSkipRule(r.ID(), r.Name(), opt.Skip.Justification, rule.Accepted)
		}
	}

	return r.AddRules(rules...)
}

func parseV1R11Options[O v1r11.RuleOption](options any) (*O, error) {
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

func getV1R11OptionOrNil[O v1r11.RuleOption](options any) (*O, error) {
	if options == nil {
		return nil, nil
	}
	return parseV1R11Options[O](options)
}
