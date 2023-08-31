// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242425{}

type Rule242425 struct {
	InstanceID              string
	ControlPlaneClient      client.Client
	ControlPlaneNamespace   string
	ClusterClient           client.Client
	ClusterCoreV1RESTClient rest.Interface
	ClusterPodContext       pod.PodContext
	Logger                  *slog.Logger
}

func (r *Rule242425) ID() string {
	return ID242425
}

func (r *Rule242425) Name() string {
	return "Kubernetes Kubelet must enable tls-cert-file for client authentication to secure service (MEDIUM 242425)"
}

func (r *Rule242425) Run(ctx context.Context) (rule.RuleResult, error) {
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

	const tlsCertFileConfigOption = "tlsCertFile"
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

		if kubeletConfig.FeatureGates == nil {
			kubeletConfig.FeatureGates = map[string]bool{}
		}

		if kubeletConfig.ServerTLSBootstrap == nil {
			// Defaults to false https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/
			kubeletConfig.ServerTLSBootstrap = pointer.Bool(false)
		}
		if _, ok := kubeletConfig.FeatureGates["RotateKubeletServerCertificate"]; !ok {
			// Defaults to true https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/
			kubeletConfig.FeatureGates["RotateKubeletServerCertificate"] = true
		}

		switch {
		case *kubeletConfig.ServerTLSBootstrap && kubeletConfig.FeatureGates["RotateKubeletServerCertificate"]:
			checkResults = append(checkResults, rule.PassedCheckResult("Kubelet rotates server certificates automatically itself.", target))
		case kubeletConfig.TLSCertFile == nil:
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s not set.", tlsCertFileConfigOption), target))
		case strings.TrimSpace(*kubeletConfig.TLSCertFile) == "":
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Option %s is empty.", tlsCertFileConfigOption), target))
		default:
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("Option %s set.", tlsCertFileConfigOption), target))
		}
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (r *Rule242425) checkWorkerGroup(ctx context.Context, workerGroup string, node utils.ReadyNode, privPodImage string) rule.CheckResult {
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
		tlsCertFileConfigOption = "tlsCertFile"
		featureGatesFlag        = "feature-gates"
		tlsCertFileFlag         = "tls-cert-file"
	)

	if utils.IsKubeletFlagSet(rawKubeletCommand, featureGatesFlag) {
		return rule.FailedCheckResult(fmt.Sprintf("Use of deprecated kubelet config flag %s.", featureGatesFlag), target)
	}

	if utils.IsKubeletFlagSet(rawKubeletCommand, tlsCertFileFlag) {
		return rule.FailedCheckResult(fmt.Sprintf("Use of deprecated kubelet config flag %s.", tlsCertFileFlag), target)
	}

	kubeletConfig, err := kubeutils.GetKubeletConfig(ctx, clusterPodExecutor, rawKubeletCommand)
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), podTarget)
	}

	if kubeletConfig.FeatureGates == nil {
		kubeletConfig.FeatureGates = map[string]bool{}
	}

	if kubeletConfig.ServerTLSBootstrap == nil {
		// Defaults to false https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/
		kubeletConfig.ServerTLSBootstrap = pointer.Bool(false)
	}
	if _, ok := kubeletConfig.FeatureGates["RotateKubeletServerCertificate"]; !ok {
		// Defaults to true https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/
		kubeletConfig.FeatureGates["RotateKubeletServerCertificate"] = true
	}

	switch {
	case *kubeletConfig.ServerTLSBootstrap && kubeletConfig.FeatureGates["RotateKubeletServerCertificate"]:
		return rule.PassedCheckResult("Kubelet rotates server certificates automatically itself.", target)
	case kubeletConfig.TLSCertFile == nil:
		return rule.FailedCheckResult(fmt.Sprintf("Option %s not set.", tlsCertFileConfigOption), target)
	case strings.TrimSpace(*kubeletConfig.TLSCertFile) == "":
		return rule.FailedCheckResult(fmt.Sprintf("Option %s is empty.", tlsCertFileConfigOption), target)
	default:
		return rule.PassedCheckResult(fmt.Sprintf("Option %s set.", tlsCertFileConfigOption), target)
	}
}
