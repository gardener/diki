// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
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
	ControlPlaneClient    client.Client
	ClusterClient         client.Client
	ControlPlaneNamespace string
	ClusterVersion        *semver.Version
	ControlPlaneVersion   *semver.Version
	ClusterV1RESTClient   rest.Interface
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

	seedTarget := rule.NewTarget("cluster", "seed")

	// featureGates.PodSecurity removed in v1.28. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
	if r.ControlPlaneVersion != nil && versionutils.ConstraintK8sGreaterEqual128.Check(r.ControlPlaneVersion) {
		checkResults = append(checkResults, rule.SkippedCheckResult(fmt.Sprintf("Option %s removed in Kubernetes v1.28.", option), seedTarget.With("details", fmt.Sprintf("Used Kubernetes version %s.", r.ControlPlaneVersion.String()))))
	} else {
		deploymentNames := []string{"kube-apiserver", "kube-controller-manager", "kube-scheduler"}
		for _, deploymentName := range deploymentNames {
			target := seedTarget.With("name", deploymentName, "namespace", r.ControlPlaneNamespace, "kind", "deployment")
			options, err := kubeutils.GetCommandOptionFromDeployment(ctx, r.ControlPlaneClient, deploymentName, deploymentName, r.ControlPlaneNamespace, "feature-gates")
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), seedTarget))
				continue
			}

			podSecurityOptions := kubeutils.FindInnerValue(options, "PodSecurity")
			// featureGates.PodSecurity defaults to true in versions >= v1.23. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/#feature-gates-for-alpha-or-beta-features
			switch {
			case len(podSecurityOptions) == 0:
				checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", option), target))
			case len(podSecurityOptions) > 1:
				checkResults = append(checkResults, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target))
			case podSecurityOptions[0] == "true":
				checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target))
			case podSecurityOptions[0] == "false":
				checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), target))
			default:
				checkResults = append(checkResults, rule.WarningCheckResult(fmt.Sprintf("Option %s set to neither 'true' nor 'false'.", option), target))
			}
		}
	}

	shootTarget := rule.NewTarget("cluster", "shoot")

	// featureGates.PodSecurity removed in v1.28. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
	if r.ClusterVersion != nil && versionutils.ConstraintK8sGreaterEqual128.Check(r.ClusterVersion) {
		checkResults = append(checkResults, rule.SkippedCheckResult(fmt.Sprintf("Option %s removed in Kubernetes v1.28.", option), shootTarget.With("details", fmt.Sprintf("Used Kubernetes version %s.", r.ClusterVersion.String()))))
	} else {
		nodes, err := kubeutils.GetNodes(ctx, r.ClusterClient, 300)
		if err != nil {
			return rule.RuleResult{
				RuleID:       r.ID(),
				RuleName:     r.Name(),
				CheckResults: append(checkResults, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "nodeList"))),
			}, nil
		}

		if len(nodes) == 0 {
			checkResults = append(checkResults, rule.WarningCheckResult("No nodes found.", shootTarget))
		}

		for _, node := range nodes {
			target := shootTarget.With("kind", "node", "name", node.Name)
			if !kubeutils.NodeReadyStatus(node) {
				checkResults = append(checkResults, rule.WarningCheckResult("Node is not in Ready state.", target))
				continue
			}

			kubeletConfig, err := kubeutils.GetNodeConfigz(ctx, r.ClusterV1RESTClient, node.Name)
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
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
