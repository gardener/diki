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

var _ rule.Rule = &Rule242425{}
var _ rule.Severity = &Rule242425{}

type Rule242425 struct {
	Client       client.Client
	V1RESTClient rest.Interface
}

func (r *Rule242425) ID() string {
	return ID242425
}

func (r *Rule242425) Name() string {
	return "Kubernetes Kubelet must enable tlsCertFile for client authentication to secure service."
}

func (r *Rule242425) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242425) Run(ctx context.Context) (rule.RuleResult, error) {
	var checkResults []rule.CheckResult

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}

	if len(nodes) == 0 {
		return rule.Result(r, rule.WarningCheckResult("No nodes found.", rule.NewTarget())), nil
	}

	const tlsCertFileConfigOption = "tlsCertFile"
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
		case kubeletConfig.TLSCertFile == nil:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s not set.", tlsCertFileConfigOption), target))
		case strings.TrimSpace(*kubeletConfig.TLSCertFile) == "":
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s is empty.", tlsCertFileConfigOption), target))
		default:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set.", tlsCertFileConfigOption), target))
		}
	}

	return rule.Result(r, checkResults...), nil
}
