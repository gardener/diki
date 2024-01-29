// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/component-base/version"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242404{}

type Rule242404 struct {
	InstanceID            string
	ControlPlaneClient    client.Client
	ControlPlaneNamespace string
	ClusterClient         client.Client
	ClusterPodContext     pod.PodContext
	Logger                *slog.Logger
}

func (r *Rule242404) ID() string {
	return ID242404
}

func (r *Rule242404) Name() string {
	return "Kubernetes Kubelet must deny hostname override (MEDIUM 242404)"
}

func (r *Rule242404) Run(ctx context.Context) (rule.RuleResult, error) {
	shootTarget := rule.NewTarget("cluster", "shoot")
	clusterNodes, err := kubeutils.GetNodes(ctx, r.ClusterClient, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "nodeList"))), nil
	}

	clusterPods, err := kubeutils.GetPods(ctx, r.ClusterClient, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "podList"))), nil
	}

	clusterWorkers, err := utils.GetWorkers(ctx, r.ControlPlaneClient, r.ControlPlaneNamespace, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("cluster", "seed", "kind", "workerList"))), nil
	}

	image, err := imagevector.ImageVector().FindImage(ruleset.DikiOpsImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", ruleset.DikiOpsImageName, err)
	}

	// check if tag is not present and use diki's version as a default
	if image.Tag == nil {
		tag := version.Get().GitVersion
		image.Tag = &tag
	}

	checkResults := []rule.CheckResult{}
	nodesAllocatablePodsNum := kubeutils.GetNodesAllocatablePodsNum(clusterPods, clusterNodes)
	workerGroupNodes := utils.GetSingleAllocatableNodePerWorker(clusterWorkers, clusterNodes, nodesAllocatablePodsNum)

	// TODO use maps.Keys when released with go 1.21 or 1.22
	workerGroups := make([]string, 0, len(workerGroupNodes))
	for workerGroup := range workerGroupNodes {
		workerGroups = append(workerGroups, workerGroup)
	}
	slices.Sort(workerGroups)

	for _, workerGroup := range workerGroups {
		node, ok := workerGroupNodes[workerGroup]
		if !ok {
			// this should never happen
			checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("Failed retrieving node for worker group %s", workerGroup), rule.NewTarget()))
			continue
		}
		checkResult := r.checkWorkerGroup(ctx, workerGroup, node, image.String())
		checkResults = append(checkResults, checkResult)
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (r *Rule242404) checkWorkerGroup(ctx context.Context, workerGroup string, node utils.AllocatableNode, privPodImage string) rule.CheckResult {
	target := rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", workerGroup)
	if !node.Allocatable {
		return rule.WarningCheckResult("There are no ready nodes with at least 1 allocatable spot for worker group.", target)
	}

	podName := fmt.Sprintf("diki-%s-%s", IDNodeFiles, Generator.Generate(10))
	podTarget := rule.NewTarget("cluster", "shoot", "kind", "pod", "namespace", "kube-system", "name", podName)

	defer func() {
		if err := r.ClusterPodContext.Delete(ctx, podName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()

	additionalLabels := map[string]string{
		pod.LabelInstanceID: r.InstanceID,
	}
	clusterPodExecutor, err := r.ClusterPodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", privPodImage, node.Node.Name, additionalLabels))
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), podTarget)
	}

	rawKubeletCommand, err := kubeutils.GetKubeletCommand(ctx, clusterPodExecutor)
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), podTarget)
	}

	const hostnameOverrideFlag = "hostname-override"

	// hostname-override does not exist in the kubelet config file. We can check if the hostname-override flag is set to validate the rule. ref https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/
	if kubeutils.IsFlagSet(rawKubeletCommand, hostnameOverrideFlag) {
		return rule.FailedCheckResult(fmt.Sprintf("Flag %s set.", hostnameOverrideFlag), target)
	}

	return rule.PassedCheckResult(fmt.Sprintf("Flag %s not set.", hostnameOverrideFlag), target)
}
