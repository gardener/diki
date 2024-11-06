// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"

	"github.com/Masterminds/semver/v3"
	versionutils "github.com/gardener/gardener/pkg/utils/version"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242399{}

type Rule242399 struct {
	Client            client.Client
	KubernetesVersion *semver.Version
	V1RESTClient      rest.Interface
}

func (r *Rule242399) ID() string {
	return ID242399
}

func (r *Rule242399) Name() string {
	return "Kubernetes DynamicKubeletConfig must not be enabled (MEDIUM 242399)"
}

func (r *Rule242399) Run(ctx context.Context) (rule.RuleResult, error) {
	const option = "featureGates.DynamicKubeletConfig"
	var checkResults []rule.CheckResult

	// featureGates.DynamicKubeletConfig removed in v1.26. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
	if r.KubernetesVersion != nil && versionutils.ConstraintK8sGreaterEqual126.Check(r.KubernetesVersion) {
		return rule.Result(r, rule.SkippedCheckResult(fmt.Sprintf("Option %s removed in Kubernetes v1.26.", option), rule.NewTarget("details", fmt.Sprintf("Used Kubernetes version %s.", r.KubernetesVersion.String())))), nil
	}

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}

	if len(nodes) == 0 {
		return rule.Result(r, rule.WarningCheckResult("No nodes found.", rule.NewTarget())), nil
	}

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

		// featureGates.DynamicKubeletConfig is deprecated in v1.22, defaults to false. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
		if dynamicKubeletConfig, ok := kubeletConfig.FeatureGates["DynamicKubeletConfig"]; !ok {
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", option), target))
		} else if dynamicKubeletConfig {
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), target))
		} else {
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target))
		}
	}

	return rule.Result(r, checkResults...), nil
}
