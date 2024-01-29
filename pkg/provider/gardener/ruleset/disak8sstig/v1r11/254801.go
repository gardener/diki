// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/Masterminds/semver"
	versionutils "github.com/gardener/gardener/pkg/utils/version"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/version"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule254801{}

type Rule254801 struct {
	InstanceID              string
	ControlPlaneClient      client.Client
	ControlPlaneNamespace   string
	ClusterClient           client.Client
	ClusterVersion          *semver.Version
	ClusterCoreV1RESTClient rest.Interface
	ClusterPodContext       pod.PodContext
	Logger                  *slog.Logger
}

func (r *Rule254801) ID() string {
	return ID254801
}

func (r *Rule254801) Name() string {
	return "Kubernetes must enable PodSecurity admission controller on static pods and Kubelets (HIGH 254801)"
}

func (r *Rule254801) Run(ctx context.Context) (rule.RuleResult, error) {
	shootTarget := rule.NewTarget("cluster", "shoot")
	const option = "featureGates.PodSecurity"

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

		// featureGates.PodSecurity defaults to false in v1.22 and to true in versions >= v1.23. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/#feature-gates-for-alpha-or-beta-features
		podSecurityConfig, ok := kubeletConfig.FeatureGates["PodSecurity"]
		switch {
		case !ok && versionutils.ConstraintK8sEqual122.Check(r.ClusterVersion):
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s not set.", option), target.With("details", fmt.Sprintf("Cluster uses Kubernetes %s.", r.ClusterVersion.String()))))
		case !ok:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", option), target.With("details", fmt.Sprintf("Cluster uses Kubernetes %s.", r.ClusterVersion.String()))))
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

func (r *Rule254801) checkWorkerGroup(ctx context.Context, workerGroup string, node utils.AllocatableNode, privPodImage string) rule.CheckResult {
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
		option = "featureGates.PodSecurity"
		flag   = "feature-gates"
	)

	if kubeutils.IsFlagSet(rawKubeletCommand, flag) {
		return rule.FailedCheckResult(fmt.Sprintf("Use of deprecated kubelet config flag %s.", flag), target)
	}

	kubeletConfig, err := kubeutils.GetKubeletConfig(ctx, clusterPodExecutor, rawKubeletCommand)
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), podTarget)
	}

	if kubeletConfig.FeatureGates == nil {
		kubeletConfig.FeatureGates = map[string]bool{}
	}

	// featureGates.PodSecurity defaults to false in v1.22 and to true in versions >= v1.23. ref https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/#feature-gates-for-alpha-or-beta-features
	podSecurityConfig, ok := kubeletConfig.FeatureGates["PodSecurity"]
	switch {
	case !ok && versionutils.ConstraintK8sEqual122.Check(r.ClusterVersion):
		return rule.FailedCheckResult(fmt.Sprintf("Option %s not set.", option), target.With("details", fmt.Sprintf("Cluster uses Kubernetes %s.", r.ClusterVersion.String())))
	case !ok:
		return rule.PassedCheckResult(fmt.Sprintf("Option %s not set.", option), target.With("details", fmt.Sprintf("Cluster uses Kubernetes %s.", r.ClusterVersion.String())))
	case podSecurityConfig:
		return rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target)
	default:
		return rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option), target)
	}
}
