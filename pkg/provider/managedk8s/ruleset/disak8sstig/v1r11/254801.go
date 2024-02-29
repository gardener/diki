// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"

	"github.com/Masterminds/semver/v3"
	versionutils "github.com/gardener/gardener/pkg/utils/version"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ rule.Rule = &Rule254801{}

type Rule254801 struct {
	Client            client.Client
	KubernetesVersion *semver.Version
	V1RESTClient      rest.Interface
}

func (r *Rule254801) ID() string {
	return sharedv1r11.ID254801
}

func (r *Rule254801) Name() string {
	return "Kubernetes must enable PodSecurity admission controller on static pods and Kubelets (HIGH 254801)"
}

func (r *Rule254801) Run(ctx context.Context) (rule.RuleResult, error) {
	const option = "featureGates.PodSecurity"
	checkResults := []rule.CheckResult{}

	// featureGates.PodSecurity removed in v1.28. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
	if r.KubernetesVersion != nil && versionutils.ConstraintK8sGreaterEqual128.Check(r.KubernetesVersion) {
		return rule.SingleCheckResult(r, rule.SkippedCheckResult(fmt.Sprintf("Option %s removed in Kubernetes v1.28.", option), rule.NewTarget("details", fmt.Sprintf("Used Kubernetes version %s.", r.KubernetesVersion.String())))), nil
	}

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}

	if len(nodes) == 0 {
		return rule.SingleCheckResult(r, rule.WarningCheckResult("No nodes found.", rule.NewTarget())), nil
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

		// featureGates.PodSecurity defaults to true in versions >= v1.23. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/#feature-gates-for-alpha-or-beta-features
		podSecurityConfig, ok := kubeletConfig.FeatureGates["PodSecurity"]
		switch {
		case !ok:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", option), target))
		case podSecurityConfig:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target))
		default:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), target))
		}
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
