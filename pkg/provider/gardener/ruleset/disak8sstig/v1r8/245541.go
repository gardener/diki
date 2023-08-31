// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule245541{}

type Rule245541 struct {
	InstanceID              string
	ControlPlaneClient      client.Client
	ControlPlaneNamespace   string
	ClusterClient           client.Client
	ClusterCoreV1RESTClient rest.Interface
	ClusterPodContext       pod.PodContext
	Logger                  *slog.Logger
}

func (r *Rule245541) ID() string {
	return ID245541
}

func (r *Rule245541) Name() string {
	return "Kubernetes Kubelet must enable kernel protection (HIGH 245541)"
}

func (r *Rule245541) Run(ctx context.Context) (rule.RuleResult, error) {
	shootTarget := gardener.NewTarget("cluster", "shoot")
	clusterNodes, err := utils.GetNodes(ctx, r.ClusterClient, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "nodeList"))), nil
	}

	clusterWorkers, err := utils.GetWorkers(ctx, r.ControlPlaneClient, r.ControlPlaneNamespace, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), gardener.NewTarget("cluster", "seed", "kind", "workerList"))), nil
	}

	image, err := imagevector.ImageVector().FindImage(ruleset.OpsToolbeltImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", ruleset.OpsToolbeltImageName, err)
	}

	workerGroupNodes := utils.GetSingleRunningNodePerWorker(clusterWorkers, clusterNodes)

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
			checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("Failed retrieving node for worker group %s", workerGroup), gardener.NewTarget()))
			continue
		}
		checkResult := r.checkWorkerGroup(ctx, workerGroup, node, image.String())
		checkResults = append(checkResults, checkResult)
	}

	const option = "streamingConnectionIdleTimeout"
	for _, clusterNode := range clusterNodes {
		target := shootTarget.With("kind", "node", "name", clusterNode.Name)
		if !utils.NodeReadyStatus(clusterNode) {
			checkResults = append(checkResults, rule.WarningCheckResult("Node is not in Ready state.", target))
			continue
		}

		kubeletConfig, err := kubeutils.GetNodeConfigz(ctx, r.ClusterCoreV1RESTClient, clusterNode.Name)
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

func (r *Rule245541) checkWorkerGroup(ctx context.Context, workerGroup string, node utils.ReadyNode, privPodImage string) rule.CheckResult {
	target := gardener.NewTarget("cluster", "seed", "kind", "workerGroup", "name", workerGroup)
	if !node.Ready {
		return rule.WarningCheckResult("There are no nodes in Ready state for worker group.", target)
	}

	podName := fmt.Sprintf("diki-%s-%s", IDNodeFiles, Generator.Generate(10))
	podTarget := gardener.NewTarget("cluster", "shoot", "kind", "pod", "namespace", "kube-system", "name", podName)

	defer func() {
		if err := r.ClusterPodContext.Delete(ctx, podName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()

	additionalLabels := map[string]string{
		gardener.LabelInstanceID: r.InstanceID,
	}
	clusterPodExecutor, err := r.ClusterPodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", privPodImage, node.Node.Name, additionalLabels))
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), podTarget)
	}

	rawKubeletCommand, err := utils.GetKubeletCommand(ctx, clusterPodExecutor)
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), podTarget)
	}

	const (
		option = "streamingConnectionIdleTimeout"
		flag   = "streaming-connection-idle-timeout"
	)

	if utils.IsKubeletFlagSet(rawKubeletCommand, flag) {
		return rule.FailedCheckResult(fmt.Sprintf("Use of deprecated kubelet config flag %s.", flag), target)
	}

	kubeletConfig, err := kubeutils.GetKubeletConfig(ctx, clusterPodExecutor, rawKubeletCommand)
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), podTarget)
	}

	// streamingConnectionIdleTimeout defaults to allowed, but not recommended value 4h. ref https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/
	if kubeletConfig.StreamingConnectionIdleTimeout == nil {
		return rule.FailedCheckResult(fmt.Sprintf("Option %s not set.", option), target)
	}

	streamingConnectionIdleTimeout, err := time.ParseDuration(*kubeletConfig.StreamingConnectionIdleTimeout)
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), podTarget)
	}

	switch {
	case streamingConnectionIdleTimeout < time.Minute*5:
		return rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option),
			target.With("details", fmt.Sprintf("%s set to %s.", option, streamingConnectionIdleTimeout.String())))
	case streamingConnectionIdleTimeout == time.Minute*5:
		return rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed value.", option), target)
	case streamingConnectionIdleTimeout <= time.Hour*4:
		return rule.PassedCheckResult(fmt.Sprintf("Option %s set to allowed, but not recommended value (should be 5m).", option),
			target.With("details", fmt.Sprintf("%s set to %s.", option, streamingConnectionIdleTimeout.String())))
	default:
		return rule.FailedCheckResult(fmt.Sprintf("Option %s set to not allowed value.", option),
			target.With("details", fmt.Sprintf("%s set to %s.", option, streamingConnectionIdleTimeout.String())))
	}
}
