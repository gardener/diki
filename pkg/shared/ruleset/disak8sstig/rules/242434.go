// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule242434{}
	_ rule.Severity = &Rule242434{}
)

type Rule242434 struct {
	Client       client.Client
	V1RESTClient rest.Interface
}

func (r *Rule242434) ID() string {
	return ID242434
}

func (r *Rule242434) Name() string {
	return "Kubernetes Kubelet must enable kernel protection."
}

func (r *Rule242434) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule242434) Run(ctx context.Context) (rule.RuleResult, error) {
	var checkResults []rule.CheckResult

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "NodeList"))), nil
	}

	if len(nodes) == 0 {
		return rule.Result(r, rule.WarningCheckResult("No nodes found.", rule.NewTarget())), nil
	}

	const protectKernelDefaultsConfigOption = "protectKernelDefaults"
	for _, node := range nodes {
		target := kubeutils.TargetWithK8sObject(rule.NewTarget(), metav1.TypeMeta{Kind: "Node"}, node.ObjectMeta)
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

	return rule.Result(r, checkResults...), nil
}
