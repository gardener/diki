// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"strconv"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242387{}

type Rule242387 struct {
	Client       client.Client
	V1RESTClient rest.Interface
}

func (r *Rule242387) ID() string {
	return ID242387
}

func (r *Rule242387) Name() string {
	return `The Kubernetes Kubelet must have the "readOnlyPort" flag disabled (HIGH 242387)`
}

func (r *Rule242387) Run(ctx context.Context) (rule.RuleResult, error) {
	var checkResults []rule.CheckResult

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}

	if len(nodes) == 0 {
		return rule.Result(r, rule.WarningCheckResult("No nodes found.", rule.NewTarget())), nil
	}

	const readOnlyPortConfigOption = "readOnlyPort"
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

		// readOnlyPort defaults to allowed value disabled. ref https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/
		switch {
		case kubeletConfig.ReadOnlyPort == nil:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", readOnlyPortConfigOption), target))
		case *kubeletConfig.ReadOnlyPort == 0:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", readOnlyPortConfigOption), target))
		default:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", readOnlyPortConfigOption), target.With("details", fmt.Sprintf("Read only port set to %s", strconv.Itoa(int(*kubeletConfig.ReadOnlyPort))))))
		}
	}

	return rule.Result(r, checkResults...), nil
}
