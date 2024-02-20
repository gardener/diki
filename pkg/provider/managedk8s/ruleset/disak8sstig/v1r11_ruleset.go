// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"encoding/json"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

func (r *Ruleset) registerV1R11Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
	client, err := client.New(r.Config, client.Options{})
	if err != nil {
		return err
	}

	podContext, err := pod.NewSimplePodContext(client, r.Config)
	if err != nil {
		return err
	}

	opts242406, err := getV1R11OptionOrNil[sharedv1r11.Options242406](ruleOptions[sharedv1r11.ID242406].Args)
	if err != nil {
		return err
	}
	opts242407, err := getV1R11OptionOrNil[sharedv1r11.Options242407](ruleOptions[sharedv1r11.ID242407].Args)
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
	opts242417, err := getV1R11OptionOrNil[sharedv1r11.Options242417](ruleOptions[sharedv1r11.ID242417].Args)
	if err != nil {
		return err
	}
	opts242447, err := getV1R11OptionOrNil[sharedv1r11.Options242447](ruleOptions[sharedv1r11.ID242447].Args)
	if err != nil {
		return err
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
			"The Kubernetes API Server must enable Node,RBAC as the authorization mode (MEDIUM242382)",
			noControlPlaneMsg,
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242383,
			"User-managed resources must be created in dedicated namespaces (HIGH 242383)",
			"",
			rule.NotImplemented,
		),
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
		rule.NewSkipRule(
			sharedv1r11.ID242387,
			"The Kubernetes Kubelet must have the read-only port flag disabled (HIGH 242387)",
			"",
			rule.NotImplemented,
		),
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
		rule.NewSkipRule(
			sharedv1r11.ID242391,
			"The Kubernetes Kubelet must have anonymous authentication disabled (HIGH 242391)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242392,
			"The Kubernetes kubelet must enable explicit authorization (HIGH 242392)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242393,
			"Kubernetes Worker Nodes must not have sshd service running (MEDIUM 242393)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242394,
			"Kubernetes Worker Nodes must not have the sshd service enabled (MEDIUM 242394)",
			"",
			rule.NotImplemented,
		),
		&sharedv1r11.Rule242395{Client: client},
		rule.NewSkipRule(
			sharedv1r11.ID242396,
			"Kubernetes Kubectl cp command must give expected access and results (MEDIUM 242396)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242397,
			"Kubernetes kubelet static PodPath must not enable static pods (HIGH 242397)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			// feature-gates.DynamicAuditing removed in v1.19. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
			sharedv1r11.ID242398,
			"Kubernetes DynamicAuditing must not be enabled (MEDIUM 242398)",
			"Option feature-gates.DynamicAuditing was removed in Kubernetes v1.19.",
			rule.Skipped,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242399,
			"Kubernetes DynamicKubeletConfig must not be enabled (MEDIUM 242399)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242400,
			"The Kubernetes API server must have Alpha APIs disabled (MEDIUM 242400)",
			"",
			rule.NotImplemented,
		),
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
		rule.NewSkipRule(
			sharedv1r11.ID242404,
			"Kubernetes Kubelet must deny hostname override (MEDIUM 242404)",
			"",
			rule.NotImplemented,
		),
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
		rule.NewSkipRule(
			sharedv1r11.ID242420,
			"Kubernetes Kubelet must have the SSL Certificate Authority set (MEDIUM 242420)",
			"",
			rule.NotImplemented,
		),
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
		rule.NewSkipRule(
			sharedv1r11.ID242424,
			"Kubernetes Kubelet must enable tlsPrivateKeyFile for client authentication to secure service (MEDIUM 242424)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242425,
			"Kubernetes Kubelet must enable tlsCertFile for client authentication to secure service (MEDIUM 242425)",
			"",
			rule.NotImplemented,
		),
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
		rule.NewSkipRule(
			sharedv1r11.ID242434,
			"Kubernetes Kubelet must enable kernel protection (HIGH 242434)",
			"",
			rule.NotImplemented,
		),
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
		rule.NewSkipRule(
			sharedv1r11.ID242442,
			"Kubernetes must remove old components after updated versions have been installed (MEDIUM 242442)",
			"",
			rule.NotImplemented,
		),
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
		rule.NewSkipRule(
			sharedv1r11.ID242448,
			"The Kubernetes Kube Proxy kubeconfig must be owned by root (MEDIUM 242448)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242449,
			"The Kubernetes Kubelet certificate authority file must have file permissions set to 644 or more restrictive (MEDIUM 242449)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242450,
			"The Kubernetes Kubelet certificate authority must be owned by root (MEDIUM 242450)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242451,
			"The Kubernetes component PKI must be owned by root (MEDIUM 242451)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242452,
			"The Kubernetes kubelet KubeConfig must have file permissions set to 644 or more restrictive (MEDIUM 242452)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242453,
			"The Kubernetes kubelet KubeConfig file must be owned by root (MEDIUM 242453)",
			"",
			rule.NotImplemented,
		),
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
		rule.NewSkipRule(
			sharedv1r11.ID242466,
			"The Kubernetes PKI CRT must have file permissions set to 644 or more restrictive (MEDIUM 242466)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			sharedv1r11.ID242467,
			"The Kubernetes PKI keys must have file permissions set to 600 or more restrictive (MEDIUM 242467)",
			"",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			sharedv1r11.ID245541,
			"Kubernetes Kubelet must not disable timeouts (MEDIUM 245541)",
			"",
			rule.NotImplemented,
		),
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
			sharedv1r11.ID254801,
			"Kubernetes must enable PodSecurity admission controller on static pods and Kubelets (HIGH 254801)",
			"",
			rule.NotImplemented,
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

	return &parsedOptions, nil
}

func getV1R11OptionOrNil[O v1r11.RuleOption](options any) (*O, error) {
	if options == nil {
		return nil, nil
	}
	return parseV1R11Options[O](options)
}
