// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242420{}

type Rule242420 struct {
	Client       client.Client
	V1RESTClient rest.Interface
}

func (r *Rule242420) ID() string {
	return ID242420
}

func (r *Rule242420) Name() string {
	return "Kubernetes Kubelet must have the SSL Certificate Authority set (MEDIUM 242420)"
}

func (r *Rule242420) Run(ctx context.Context) (rule.RuleResult, error) {
	var checkResults []rule.CheckResult

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}

	if len(nodes) == 0 {
		return rule.Result(r, rule.WarningCheckResult("No nodes found.", rule.NewTarget())), nil
	}

	const clientCAFileConfigOption = "authentication.x509.clientCAFile"
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

		switch {
		case kubeletConfig.Authentication.X509.ClientCAFile == nil:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s not set.", clientCAFileConfigOption), target))
		case strings.TrimSpace(*kubeletConfig.Authentication.X509.ClientCAFile) == "":
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s is empty.", clientCAFileConfigOption), target))
		default:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set.", clientCAFileConfigOption), target))
		}
	}

	return rule.Result(r, checkResults...), nil
}
