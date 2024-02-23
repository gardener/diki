// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242434{}

type Rule242434 struct {
	Client       client.Client
	V1RESTClient rest.Interface
}

func (r *Rule242434) ID() string {
	return ID242434
}

func (r *Rule242434) Name() string {
	return "Kubernetes Kubelet must enable kernel protection (HIGH 242434)"
}

func (r *Rule242434) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}

	if len(nodes) == 0 {
		return rule.SingleCheckResult(r, rule.WarningCheckResult("No nodes found.", rule.NewTarget())), nil
	}

	const protectKernelDefaultsConfigOption = "protectKernelDefaults"
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

		// protectKernelDefaults defaults to not allowed value false. ref https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/
		switch {
		case kubeletConfig.ProtectKernelDefaults == nil:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s not set.", protectKernelDefaultsConfigOption), target))
		case *kubeletConfig.ProtectKernelDefaults:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", protectKernelDefaultsConfigOption), target))
		default:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", protectKernelDefaultsConfigOption), target))
		}
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
