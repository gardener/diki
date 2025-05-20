// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/rule/retry"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/retryerrors"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

func (r *Ruleset) registerV2R3Rules(ruleOptions map[string]config.RuleOptionsConfig) error { // TODO: add to FromGenericConfig
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

	authorityCertPool := x509.NewCertPool()
	ok := authorityCertPool.AppendCertsFromPEM(r.Config.CAData)
	if !ok {
		return fmt.Errorf("failed to parse kube-apiserver CA data from config")
	}

	opts242383, err := getV2R3OptionOrNil[sharedrules.Options242383](ruleOptions[sharedrules.ID242383].Args)
	if err != nil {
		return fmt.Errorf("rule option 242383 error: %s", err.Error())
	}
	opts242393, err := getV2R3OptionOrNil[sharedrules.Options242393](ruleOptions[sharedrules.ID242393].Args)
	if err != nil {
		return fmt.Errorf("rule option 242393 error: %s", err.Error())
	}
	opts242394, err := getV2R3OptionOrNil[sharedrules.Options242394](ruleOptions[sharedrules.ID242394].Args)
	if err != nil {
		return fmt.Errorf("rule option 242394 error: %s", err.Error())
	}
	opts242396, err := getV2R3OptionOrNil[sharedrules.Options242396](ruleOptions[sharedrules.ID242396].Args)
	if err != nil {
		return fmt.Errorf("rule option 242396 error: %s", err.Error())
	}
	opts242400, err := getV2R3OptionOrNil[rules.Options242400](ruleOptions[sharedrules.ID242400].Args)
	if err != nil {
		return fmt.Errorf("rule option 242400 error: %s", err.Error())
	}
	opts242404, err := getV2R3OptionOrNil[sharedrules.Options242404](ruleOptions[sharedrules.ID242404].Args)
	if err != nil {
		return fmt.Errorf("rule option 242404 error: %s", err.Error())
	}
	opts242406, err := getV2R3OptionOrNil[sharedrules.Options242406](ruleOptions[sharedrules.ID242406].Args)
	if err != nil {
		return fmt.Errorf("rule option 242406 error: %s", err.Error())
	}
	opts242407, err := getV2R3OptionOrNil[sharedrules.Options242407](ruleOptions[sharedrules.ID242407].Args)
	if err != nil {
		return fmt.Errorf("rule option 242407 error: %s", err.Error())
	}
	opts242414, err := getV2R3OptionOrNil[option.Options242414](ruleOptions[sharedrules.ID242414].Args)
	if err != nil {
		return fmt.Errorf("rule option 242414 error: %s", err.Error())
	}
	opts242415, err := getV2R3OptionOrNil[option.Options242415](ruleOptions[sharedrules.ID242415].Args)
	if err != nil {
		return fmt.Errorf("rule option 242415 error: %s", err.Error())
	}
	opts242417, err := getV2R3OptionOrNil[sharedrules.Options242417](ruleOptions[sharedrules.ID242417].Args)
	if err != nil {
		return fmt.Errorf("rule option 242417 error: %s", err.Error())
	}
	opts242442, err := getV2R3OptionOrNil[rules.Options242442](ruleOptions[sharedrules.ID242442].Args)
	if err != nil {
		return fmt.Errorf("rule option 242442 error: %s", err.Error())
	}
	opts242447, err := getV2R3OptionOrNil[sharedrules.Options242447](ruleOptions[sharedrules.ID242447].Args)
	if err != nil {
		return fmt.Errorf("rule option 242447 error: %s", err.Error())
	}
	opts242448, err := getV2R3OptionOrNil[sharedrules.Options242448](ruleOptions[sharedrules.ID242448].Args)
	if err != nil {
		return fmt.Errorf("rule option 242448 error: %s", err.Error())
	}
	opts242449, err := getV2R3OptionOrNil[sharedrules.Options242449](ruleOptions[sharedrules.ID242449].Args)
	if err != nil {
		return fmt.Errorf("rule option 242449 error: %s", err.Error())
	}
	opts242450, err := getV2R3OptionOrNil[sharedrules.Options242450](ruleOptions[sharedrules.ID242450].Args)
	if err != nil {
		return fmt.Errorf("rule option 242450 error: %s", err.Error())
	}
	opts242451, err := getV2R3OptionOrNil[rules.Options242451](ruleOptions[sharedrules.ID242451].Args)
	if err != nil {
		return fmt.Errorf("rule option 242451 error: %s", err.Error())
	}
	opts242452, err := getV2R3OptionOrNil[sharedrules.Options242452](ruleOptions[sharedrules.ID242452].Args)
	if err != nil {
		return fmt.Errorf("rule option 242452 error: %s", err.Error())
	}
	opts242453, err := getV2R3OptionOrNil[sharedrules.Options242453](ruleOptions[sharedrules.ID242453].Args)
	if err != nil {
		return fmt.Errorf("rule option 242453 error: %s", err.Error())
	}
	opts242466, err := getV2R3OptionOrNil[rules.Options242466](ruleOptions[sharedrules.ID242466].Args)
	if err != nil {
		return fmt.Errorf("rule option 242466 error: %s", err.Error())
	}
	opts242467, err := getV2R3OptionOrNil[rules.Options242467](ruleOptions[sharedrules.ID242467].Args)
	if err != nil {
		return fmt.Errorf("rule option 242467 error: %s", err.Error())
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

	const (
		noControlPlaneMsg = "The Managed Kubernetes cluster does not have access to control plane components."
	)
	rules := []rule.Rule{
		rule.NewSkipRule(
			sharedrules.ID242376,
			"The Kubernetes Controller Manager must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242377,
			"The Kubernetes Scheduler must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242378,
			"The Kubernetes API Server must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242379,
			"The Kubernetes etcd must use TLS to protect the confidentiality of sensitive data during electronic dissemination.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242380,
			"The Kubernetes etcd must use TLS to protect the confidentiality of sensitive data during electronic dissemination.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242381,
			"The Kubernetes Controller Manager must create unique service accounts for each work payload.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			sharedrules.ID242382,
			"The Kubernetes API Server must enable Node,RBAC as the authorization mode.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		&sharedrules.Rule242383{
			Client:  client,
			Options: opts242383,
		},
		rule.NewSkipRule(
			sharedrules.ID242384,
			"The Kubernetes Scheduler must have secure binding.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242385,
			"The Kubernetes Controller Manager must have secure binding.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242386,
			"The Kubernetes API server must have the insecure port flag disabled.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		&sharedrules.Rule242387{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		rule.NewSkipRule(
			sharedrules.ID242388,
			"The Kubernetes API server must have the insecure bind address not set.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			sharedrules.ID242389,
			"The Kubernetes API server must have the secure port set.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		&rules.Rule242390{
			KAPIExternalURL: r.Config.Host,
			Client: &http.Client{
				Transport: &http.Transport{
					// the TLS MinVersion warnings are ignored in order to avoid version conflicts
					TLSClientConfig: &tls.Config{ // #nosec: G402
						RootCAs: authorityCertPool,
					},
				},
			},
		},
		&sharedrules.Rule242391{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		&sharedrules.Rule242392{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242393)),
			retry.WithBaseRule(&sharedrules.Rule242393{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242393),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242393,
			}),
			retry.WithRetryCondition(rcOpsPod),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242394)),
			retry.WithBaseRule(&sharedrules.Rule242394{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242394),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242394,
			}),
			retry.WithRetryCondition(rcOpsPod),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		&sharedrules.Rule242395{Client: client},
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242396)),
			retry.WithBaseRule(&sharedrules.Rule242396{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242396),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242396,
			}),
			retry.WithRetryCondition(rcOpsPod),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		&sharedrules.Rule242397{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
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
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242400)),
			retry.WithBaseRule(&rules.Rule242400{
				Logger:       r.Logger().With("rule_id", sharedrules.ID242400),
				InstanceID:   r.instanceID,
				Client:       client,
				PodContext:   podContext,
				V1RESTClient: clientSet.CoreV1().RESTClient(),
				Options:      opts242400,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),

		rule.NewSkipRule(
			sharedrules.ID242402,
			"The Kubernetes API Server must have an audit log path set.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242403,
			"Kubernetes API Server must generate audit records that identify what type of event has occurred, identify the source of the event, contain the event results, identify any users, and identify any containers associated with the event.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242404)),
			retry.WithBaseRule(&sharedrules.Rule242404{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242404),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242404,
			}),
			retry.WithRetryCondition(rcOpsPod),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		rule.NewSkipRule(
			sharedrules.ID242405,
			"Kubernetes manifests must be owned by root.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242406)),
			retry.WithBaseRule(&sharedrules.Rule242406{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242406),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242406,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242407)),
			retry.WithBaseRule(&sharedrules.Rule242407{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242407),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242407,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		rule.NewSkipRule(
			sharedrules.ID242408,
			"The Kubernetes manifest files must have least privileges.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242409,
			"Kubernetes Controller Manager must disable profiling.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242410,
			"The Kubernetes API Server must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242411,
			"The Kubernetes Scheduler must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242412,
			"The Kubernetes Controllers must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242413,
			"The Kubernetes etcd must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		&rules.Rule242414{
			Client:  client,
			Options: opts242414,
		},
		&rules.Rule242415{
			Client:  client,
			Options: opts242415,
		},
		&sharedrules.Rule242417{
			Client:  client,
			Options: opts242417,
		},
		rule.NewSkipRule(
			sharedrules.ID242418,
			"The Kubernetes API server must use approved cipher suites.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242419,
			"Kubernetes API Server must have the SSL Certificate Authority set.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		&sharedrules.Rule242420{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		rule.NewSkipRule(
			sharedrules.ID242421,
			"Kubernetes Controller Manager must have the SSL Certificate Authority set.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242422,
			"Kubernetes API Server must have a certificate for communication.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242423,
			"Kubernetes etcd must enable client authentication to secure service.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		&sharedrules.Rule242424{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		&sharedrules.Rule242425{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		rule.NewSkipRule(
			sharedrules.ID242426,
			"Kubernetes etcd must enable client authentication to secure service.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242427,
			"Kubernetes etcd must have a key file for secure communication.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242428,
			"Kubernetes etcd must have a certificate for communication.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242429,
			"Kubernetes etcd must have the SSL Certificate Authority set.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242430,
			"Kubernetes etcd must have a certificate for communication.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242431,
			"Kubernetes etcd must have a key file for secure communication.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242432,
			"Kubernetes etcd must have peer-cert-file set for secure communication.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242433,
			"Kubernetes etcd must have a peer-key-file set for secure communication.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		&sharedrules.Rule242434{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		rule.NewSkipRule(
			sharedrules.ID242436,
			"The Kubernetes API server must have the ValidatingAdmissionWebhook enabled.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			sharedrules.ID242437,
			"Kubernetes must have a pod security policy set.",
			"PSPs are removed in K8s version 1.25.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			sharedrules.ID242438,
			"Kubernetes API Server must configure timeouts to limit attack surface.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		&rules.Rule242442{
			// We check only system (kube-proxy) pods in this rule, since there can be a user case to run different versions of images.
			Client:  client,
			Options: opts242442,
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
			"Rule is duplicate of 242405. "+noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242445,
			"The Kubernetes component etcd must be owned by etcd.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242446,
			"The Kubernetes conf files must be owned by root.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242447)),
			retry.WithBaseRule(&sharedrules.Rule242447{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242447),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242447,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242448)),
			retry.WithBaseRule(&sharedrules.Rule242448{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242448),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242448,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242449)),
			retry.WithBaseRule(&sharedrules.Rule242449{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242449),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242449,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242450)),
			retry.WithBaseRule(&sharedrules.Rule242450{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242450),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242450,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242451)),
			retry.WithBaseRule(&rules.Rule242451{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242451),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242451,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242452)),
			retry.WithBaseRule(&sharedrules.Rule242452{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242452),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242452,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242453)),
			retry.WithBaseRule(&sharedrules.Rule242453{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242453),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242453,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
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
			"Duplicate of 242452.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242457,
			"The Kubernetes kubelet config must be owned by root.",
			"Duplicate of 242453.",
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242459,
			"The Kubernetes etcd must have file permissions set to 644 or more restrictive.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242460,
			"The Kubernetes admin kubeconfig must have file permissions set to 644 or more restrictive.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242461,
			"Kubernetes API Server audit logs must be enabled.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242462,
			"The Kubernetes API Server must be set to audit log max size.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242463,
			"The Kubernetes API Server must be set to audit log maximum backup.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242464,
			"The Kubernetes API Server audit log retention must be set.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		rule.NewSkipRule(
			sharedrules.ID242465,
			"The Kubernetes API Server audit log path must be set.",
			"Duplicate of 242402. "+noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityMedium),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242466)),
			retry.WithBaseRule(&rules.Rule242466{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242466),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242466,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		retry.New(
			retry.WithLogger(r.Logger().With("rule_id", sharedrules.ID242467)),
			retry.WithBaseRule(&rules.Rule242467{
				Logger:     r.Logger().With("rule_id", sharedrules.ID242467),
				InstanceID: r.instanceID,
				Client:     client,
				PodContext: podContext,
				Options:    opts242467,
			}),
			retry.WithRetryCondition(rcFileChecks),
			retry.WithMaxRetries(*r.args.MaxRetries),
		),
		&sharedrules.Rule245541{
			Client:       client,
			V1RESTClient: clientSet.CoreV1().RESTClient(),
		},
		rule.NewSkipRule(
			sharedrules.ID245542,
			"Kubernetes API Server must disable basic authentication to protect information in transit.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			sharedrules.ID245543,
			"Kubernetes API Server must disable token authentication to protect information in transit.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			sharedrules.ID245544,
			"Kubernetes endpoints must use approved organizational certificate and key pair to protect information in transit.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
		rule.NewSkipRule(
			sharedrules.ID254800,
			"Kubernetes must have a Pod Security Admission control file configured.",
			noControlPlaneMsg,
			rule.Skipped,
			rule.SkipRuleWithSeverity(rule.SeverityHigh),
		),
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
