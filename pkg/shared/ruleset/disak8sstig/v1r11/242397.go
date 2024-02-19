// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"slices"

	"k8s.io/client-go/rest"
	"k8s.io/component-base/version"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/images"
	"github.com/gardener/diki/pkg/shared/provider"
)

var _ rule.Rule = &Rule242397{}

type Rule242397 struct {
	Client       client.Client
	V1RESTClient rest.Interface
	Options      *Options242397
	Logger       provider.Logger
}

type Options242397 struct {
	GroupByLabels []string `json:"groupByLabels" yaml:"groupByLabels"`
}

func (r *Rule242397) ID() string {
	return ID242397
}

func (r *Rule242397) Name() string {
	return "Kubernetes kubelet static PodPath must not enable static pods (HIGH 242397)"
}

func (r *Rule242397) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}
	nodeLabels := []string{}

	if r.Options != nil && r.Options.GroupByLabels != nil {
		nodeLabels = slices.Clone(r.Options.GroupByLabels)
	}

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}

	// no execution pods are created by this rule
	// hence the allocatability of nodes does not matter
	nodesAllocatablePods := map[string]int{}
	for _, node := range nodes {
		nodesAllocatablePods[node.Name] = 1
	}

	selectedNodes, checks := kubeutils.SelectNodes(nodes, nodesAllocatablePods, nodeLabels)
	checkResults = append(checkResults, checks...)

	if len(selectedNodes) == 0 {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult("no selected nodes", rule.NewTarget())), nil
	}

	image, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
	}
	image.WithOptionalTag(version.Get().GitVersion)

	const staticPodPathConfigOption = "staticPodPath"
	for _, node := range selectedNodes {
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
		case kubeletConfig.StaticPodPath == nil:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", staticPodPathConfigOption), target))
		default:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s set.", staticPodPathConfigOption), target))
		}
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
