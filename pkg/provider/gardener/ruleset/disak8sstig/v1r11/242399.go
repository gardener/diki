// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/Masterminds/semver/v3"
	versionutils "github.com/gardener/gardener/pkg/utils/version"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/version"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/images"
)

var _ rule.Rule = &Rule242399{}

type Rule242399 struct {
	InstanceID              string
	ControlPlaneClient      client.Client
	ControlPlaneNamespace   string
	ClusterClient           client.Client
	ClusterVersion          *semver.Version
	ClusterCoreV1RESTClient rest.Interface
	ClusterPodContext       pod.PodContext
	Logger                  *slog.Logger
}

func (r *Rule242399) ID() string {
	return ID242399
}

func (r *Rule242399) Name() string {
	return "Kubernetes DynamicKubeletConfig must not be enabled (MEDIUM 242399)"
}

func (r *Rule242399) Run(ctx context.Context) (rule.RuleResult, error) {
	shootTarget := rule.NewTarget("cluster", "shoot")
	const dynamicKubeletConfigOption = "featureGates.DynamicKubeletConfig"

	// featureGates.DynamicKubeletConfig removed in v1.26. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
	if versionutils.ConstraintK8sGreaterEqual126.Check(r.ClusterVersion) {
		return rule.SingleCheckResult(r, rule.SkippedCheckResult(fmt.Sprintf("Option %s removed in Kubernetes v1.26.", dynamicKubeletConfigOption), shootTarget.With("details", fmt.Sprintf("Cluster uses Kubernetes %s.", r.ClusterVersion.String())))), nil
	}

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

	image, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
	}
	image.WithOptionalTag(version.Get().GitVersion)

	nodesAllocatablePodsNum := kubeutils.GetNodesAllocatablePodsNum(clusterPods, clusterNodes)
	workerGroupNodes := utils.GetSingleAllocatableNodePerWorker(clusterWorkers, clusterNodes, nodesAllocatablePodsNum)

	// TODO use maps.Keys when released with go 1.21 or 1.22
	workerGroups := make([]string, 0, len(workerGroupNodes))
	for workerGroup := range workerGroupNodes {
		workerGroups = append(workerGroups, workerGroup)
	}
	slices.Sort(workerGroups)

	checkResults := []rule.CheckResult{}
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

	for _, clusterNode := range clusterNodes {
		target := shootTarget.With("kind", "node", "name", clusterNode.Name)
		if !kubeutils.NodeReadyStatus(clusterNode) {
			checkResults = append(checkResults, rule.WarningCheckResult("Node is not in Ready state.", target))
			continue
		}

		kubeletConfig, err := kubeutils.GetNodeConfigz(ctx, r.ClusterCoreV1RESTClient, clusterNode.Name)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), target))
			continue
		}

		if kubeletConfig.FeatureGates == nil {
			kubeletConfig.FeatureGates = map[string]bool{}
		}

		// featureGates.DynamicKubeletConfig is depracated in v1.22, defaults to false. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
		if dynamicKubeletConfig, ok := kubeletConfig.FeatureGates["DynamicKubeletConfig"]; !ok {
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", dynamicKubeletConfigOption), target))
		} else if dynamicKubeletConfig {
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", dynamicKubeletConfigOption), target))
		} else {
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", dynamicKubeletConfigOption), target))
		}
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (r *Rule242399) checkWorkerGroup(ctx context.Context, workerGroup string, node utils.AllocatableNode, privPodImage string) rule.CheckResult {
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

	const (
		dynamicKubeletConfigOption = "featureGates.DynamicKubeletConfig"
		featureGatesFlag           = "feature-gates"
	)

	if kubeutils.IsFlagSet(rawKubeletCommand, featureGatesFlag) {
		return rule.FailedCheckResult(fmt.Sprintf("Use of deprecated kubelet config flag %s.", featureGatesFlag), target)
	}

	kubeletConfig, err := kubeutils.GetKubeletConfig(ctx, clusterPodExecutor, rawKubeletCommand)
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), podTarget)
	}

	if kubeletConfig.FeatureGates == nil {
		kubeletConfig.FeatureGates = map[string]bool{}
	}

	// featureGates.DynamicKubeletConfig is deprecated in v1.22, defaults to false. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
	if dynamicKubeletConfig, ok := kubeletConfig.FeatureGates["DynamicKubeletConfig"]; !ok {
		return rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", dynamicKubeletConfigOption), target)
	} else if dynamicKubeletConfig {
		return rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", dynamicKubeletConfigOption), target)
	}

	return rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", dynamicKubeletConfigOption), target)
}
