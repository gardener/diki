// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"time"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule245541{}

type Rule245541 struct {
	Client       client.Client
	V1RESTClient rest.Interface
}

func (r *Rule245541) ID() string {
	return ID245541
}

func (r *Rule245541) Name() string {
	return "Kubernetes Kubelet must not disable timeouts (MEDIUM 245541)"
}

func (r *Rule245541) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}

	if len(nodes) == 0 {
		return rule.Result(r, rule.WarningCheckResult("No nodes found.", rule.NewTarget())), nil
	}

	const option = "streamingConnectionIdleTimeout"
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

		// streamingConnectionIdleTimeout defaults to allowed, but not recommended value 4h. ref https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/
		if kubeletConfig.StreamingConnectionIdleTimeout == nil {
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s not set.", option), target))
			continue
		}

		streamingConnectionIdleTimeout, err := time.ParseDuration(*kubeletConfig.StreamingConnectionIdleTimeout)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), target))
			continue
		}

		switch {
		case streamingConnectionIdleTimeout < time.Minute*5:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option),
				target.With("details", fmt.Sprintf("%s set to %s.", option, streamingConnectionIdleTimeout.String()))))
		case streamingConnectionIdleTimeout == time.Minute*5:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target))
		case streamingConnectionIdleTimeout <= time.Hour*4:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed, but not recommended value (should be 5m).", option),
				target.With("details", fmt.Sprintf("%s set to %s.", option, streamingConnectionIdleTimeout.String()))))
		default:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option),
				target.With("details", fmt.Sprintf("%s set to %s.", option, streamingConnectionIdleTimeout.String()))))
		}
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
