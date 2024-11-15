// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule242424{}
	_ rule.Severity = &Rule242424{}
)

type Rule242424 struct {
	Client       client.Client
	V1RESTClient rest.Interface
}

func (r *Rule242424) ID() string {
	return ID242424
}

func (r *Rule242424) Name() string {
	return "Kubernetes Kubelet must enable tlsPrivateKeyFile for client authentication to secure service."
}

func (r *Rule242424) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242424) Run(ctx context.Context) (rule.RuleResult, error) {
	var checkResults []rule.CheckResult

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}

	if len(nodes) == 0 {
		return rule.Result(r, rule.WarningCheckResult("No nodes found.", rule.NewTarget())), nil
	}

	const tlsPrivateKeyFileConfigOption = "tlsPrivateKeyFile"
	for _, node := range nodes {
		target := rule.NewTarget("kind", "node", "name", node.Name)
		if !kubeutils.NodeReadyStatus(node) {
			checkResults = append(checkResults, rule.WarningCheckResult("Node is not in Ready state.", target))
			continue
		}

		kubeletConfig, err := kubeutils.GetNodeConfigz(ctx, r.V1RESTClient, node.Name)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), target))
			continue
		}

		if kubeletConfig.FeatureGates == nil {
			kubeletConfig.FeatureGates = map[string]bool{}
		}

		if kubeletConfig.ServerTLSBootstrap == nil {
			// Defaults to false https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/
			kubeletConfig.ServerTLSBootstrap = ptr.To(false)
		}
		if _, ok := kubeletConfig.FeatureGates["RotateKubeletServerCertificate"]; !ok {
			// Defaults to true https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/
			kubeletConfig.FeatureGates["RotateKubeletServerCertificate"] = true
		}

		switch {
		case *kubeletConfig.ServerTLSBootstrap && kubeletConfig.FeatureGates["RotateKubeletServerCertificate"]:
			// https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/#certificate-rotation
			checkResults = append(checkResults, rule.PassedCheckResult("Kubelet rotates server certificates automatically itself.", target))
		case kubeletConfig.TLSPrivateKeyFile == nil:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s not set.", tlsPrivateKeyFileConfigOption), target))
		case strings.TrimSpace(*kubeletConfig.TLSPrivateKeyFile) == "":
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s is empty.", tlsPrivateKeyFileConfigOption), target))
		default:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set.", tlsPrivateKeyFileConfigOption), target))
		}
	}

	return rule.Result(r, checkResults...), nil
}
