// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule242397{}
	_ rule.Severity = &Rule242397{}
)

type Rule242397 struct {
	Client       client.Client
	V1RESTClient rest.Interface
}

func (r *Rule242397) ID() string {
	return ID242397
}

func (r *Rule242397) Name() string {
	return "The Kubernetes kubelet staticPodPath must not enable static pods."
}

func (r *Rule242397) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule242397) Run(ctx context.Context) (rule.RuleResult, error) {
	var checkResults []rule.CheckResult

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}

	if len(nodes) == 0 {
		return rule.Result(r, rule.WarningCheckResult("No nodes found.", rule.NewTarget())), nil
	}

	const staticPodPathConfigOption = "staticPodPath"
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

		if kubeletConfig.StaticPodPath == nil {
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", staticPodPathConfigOption), target))
		} else {
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s set.", staticPodPathConfigOption), target))
		}
	}

	return rule.Result(r, checkResults...), nil
}
