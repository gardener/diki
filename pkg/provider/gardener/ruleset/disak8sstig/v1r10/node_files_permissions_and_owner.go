// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &RuleNodeFiles{}

type RuleNodeFiles struct {
	InstanceID            string
	ControlPlaneClient    client.Client
	ControlPlaneNamespace string
	ClusterClient         client.Client
	ClusterPodContext     pod.PodContext
	Logger                *slog.Logger
}

func (r *RuleNodeFiles) ID() string {
	return IDNodeFiles
}

func (r *RuleNodeFiles) Name() string {
	return "Config files for node kubelet and PKI must have required permissions and owners (242406, 242407, 242449, 242450, 242452, 242453 as well as 242451, 242466, 242467)"
}

func (r *RuleNodeFiles) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}
	expectedFileOwnerUsers := []string{"0"}
	expectedFileOwnerGroups := []string{"0", "65534"}
	kubeletFilePaths := []string{}

	podName := fmt.Sprintf("diki-%s-%s", IDNodeFiles, Generator.Generate(10))
	execPodTarget := gardener.NewTarget("cluster", "shoot", "name", podName, "namespace", "kube-system", "kind", "pod")
	image, err := imagevector.ImageVector().FindImage(ruleset.OpsToolbeltImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", ruleset.OpsToolbeltImageName, err)
	}
	defer func() {
		if err := r.ClusterPodContext.Delete(ctx, podName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()
	additionalLabels := map[string]string{
		gardener.LabelInstanceID: r.InstanceID,
	}
	podExecutor, err := r.ClusterPodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", image.String(), "", additionalLabels))
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), execPodTarget)), nil
	}

	rawKubeletCommand, err := kubeutils.GetKubeletCommand(ctx, podExecutor)
	if err != nil {
		checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("could not retrieve kubelet command: %s", err.Error()), execPodTarget))
	}

	var kubeconfigPath string
	if len(rawKubeletCommand) > 0 {
		if kubeletConfig, err := kubeutils.GetKubeletConfig(ctx, podExecutor, rawKubeletCommand); err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("could not retrieve kubelet config: %s", err.Error()), execPodTarget))
		} else {
			switch {
			case kubeletConfig.Authentication.X509.ClientCAFile == nil:
				checkResults = append(checkResults, rule.FailedCheckResult("could not find client ca path: client-ca-file not set.", execPodTarget))
			case strings.TrimSpace(*kubeletConfig.Authentication.X509.ClientCAFile) == "":
				checkResults = append(checkResults, rule.FailedCheckResult("could not find client ca path: client-ca-file is empty.", execPodTarget))
			default:
				kubeletFilePaths = append(kubeletFilePaths, *kubeletConfig.Authentication.X509.ClientCAFile) // rules 242449, 242450
			}
		}

		if kubeconfigPath, err = r.getKubeletFlagValue(rawKubeletCommand, "kubeconfig"); err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("could not find kubeconfig path: %s", err.Error()), execPodTarget))
		} else {
			kubeletFilePaths = append(kubeletFilePaths, kubeconfigPath) // not demanded, but similar in nature to rules 242452, 242453 and 242467
		}

		if kubeletConfigPath, err := r.getKubeletFlagValue(rawKubeletCommand, "config"); err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("could not find kubelet config path: %s", err.Error()), execPodTarget))
		} else {
			kubeletFilePaths = append(kubeletFilePaths, kubeletConfigPath) // rules 242452, 242453
		}
	} else {
		checkResults = append(checkResults, rule.ErroredCheckResult("could not retrieve kubelet config: kubelet command not retrived", execPodTarget),
			rule.ErroredCheckResult("could not find kubeconfig path: kubelet command not retrived", execPodTarget),
			rule.ErroredCheckResult("could not find kubelet config path: kubelet command not retrived", execPodTarget))
	}

	if kubeletServicePath, err := podExecutor.Execute(ctx, "/bin/sh", "systemctl show -P FragmentPath kubelet.service"); err != nil {
		checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("could not find kubelet.service path: %s", err.Error()), execPodTarget))
	} else {
		kubeletFilePaths = append(kubeletFilePaths, kubeletServicePath) // rules 242406, 242407
	}

	for _, kubeletFilePath := range kubeletFilePaths {
		target := gardener.NewTarget("cluster", "shoot", "details", fmt.Sprintf("filePath: %s", kubeletFilePath))
		statsRaw, err := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`stat -Lc "%%a %%u %%g %%n" %s`, kubeletFilePath))
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			continue
		}
		if len(statsRaw) == 0 {
			checkResults = append(checkResults, rule.ErroredCheckResult("Stats not found", target))
			continue
		}
		stats := strings.Split(strings.TrimSpace(statsRaw), "\n")

		expectedFilePermissionsMax := "644"
		if kubeletFilePath == kubeconfigPath {
			expectedFilePermissionsMax = "600"
		}

		for _, stat := range stats {
			statSlice := strings.Split(stat, " ")
			checkResults = append(checkResults, utils.MatchFilePermissionsAndOwnersCases(statSlice[0], statSlice[1], statSlice[2], strings.Join(statSlice[3:], " "),
				expectedFilePermissionsMax, expectedFileOwnerUsers, expectedFileOwnerGroups, target)...)
		}
	}

	if pkiAllStatsRaw, err := podExecutor.Execute(ctx, "/bin/sh", `find /var/lib/kubelet/pki -exec stat -Lc "%a %u %g %n" {} \;`); err != nil { // rule 242451
		checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
	} else if len(pkiAllStatsRaw) == 0 {
		checkResults = append(checkResults, rule.ErroredCheckResult("Stats not found", gardener.NewTarget("cluster", "shoot", "details", "filePath: /var/lib/kubelet/pki")))
	} else {
		pkiAllStats := strings.Split(strings.TrimSpace(pkiAllStatsRaw), "\n")
		for _, pkiAllStat := range pkiAllStats {
			pkiAllStatSlice := strings.Split(pkiAllStat, " ")
			checkResults = append(checkResults, utils.MatchFilePermissionsAndOwnersCases(pkiAllStatSlice[0], pkiAllStatSlice[1], pkiAllStatSlice[2], strings.Join(pkiAllStatSlice[3:], " "),
				"755", expectedFileOwnerUsers, expectedFileOwnerGroups, gardener.NewTarget("cluster", "shoot"))...)
		}
	}

	clusterNodes, err := kubeutils.GetNodes(ctx, r.ClusterClient, 512)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), gardener.NewTarget("cluster", "shoot", "kind", "nodeList"))), nil
	}

	clusterPods, err := kubeutils.GetPods(ctx, r.ClusterClient, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), gardener.NewTarget("cluster", "shoot", "kind", "podList"))), nil
	}

	clusterWorkers, err := utils.GetWorkers(ctx, r.ControlPlaneClient, r.ControlPlaneNamespace, 512)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), gardener.NewTarget("cluster", "seed", "kind", "workerList"))), nil
	}

	nodesAllocatablePodsNum := utils.GetNodesAllocatablePodsNum(clusterPods, clusterNodes)
	workerGroupNodes := utils.GetSingleAllocatableNodePerWorker(clusterWorkers, clusterNodes, nodesAllocatablePodsNum)

	orderedWorkerGroups := []string{}
	for workerGroup := range workerGroupNodes {
		orderedWorkerGroups = append(orderedWorkerGroups, workerGroup)
	}
	sort.Strings(orderedWorkerGroups)

	for _, workerGroup := range orderedWorkerGroups {
		checkResultsForWorkerGroup := r.checkWorkerGroup(ctx, image.String(), workerGroup, workerGroupNodes, expectedFileOwnerUsers, expectedFileOwnerGroups)
		checkResults = append(checkResults, checkResultsForWorkerGroup...)
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (r *RuleNodeFiles) checkWorkerGroup(ctx context.Context, image, workerGroup string, workerGroupNodes map[string]utils.AllocatableNode, expectedFileOwnerUsers, expectedFileOwnerGroups []string) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
	runningNode := workerGroupNodes[workerGroup]
	target := gardener.NewTarget("cluster", "shoot", "name", workerGroup, "kind", "workerGroup")
	if !runningNode.Allocatable {
		return []rule.CheckResult{rule.WarningCheckResult("There are no ready nodes with at least 1 allocatable spot for worker group.", target)}
	}

	nodePodName := fmt.Sprintf("diki-%s-%s", IDNodeFiles, Generator.Generate(10))
	execNodePodTarget := gardener.NewTarget("cluster", "shoot", "name", nodePodName, "namespace", "kube-system", "kind", "pod")
	defer func() {
		if err := r.ClusterPodContext.Delete(ctx, nodePodName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()
	additionalLabels := map[string]string{
		gardener.LabelInstanceID: r.InstanceID,
	}
	nodePodExecutor, err := r.ClusterPodContext.Create(
		ctx,
		pod.NewPrivilegedPod(nodePodName, "kube-system", image, runningNode.Node.Name, additionalLabels),
	)
	if err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execNodePodTarget)}
	}

	rawKubeletCommand, err := kubeutils.GetKubeletCommand(ctx, nodePodExecutor)
	if err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execNodePodTarget)}
	}

	if kubeutils.IsFlagSet(rawKubeletCommand, "feature-gates") {
		return []rule.CheckResult{rule.FailedCheckResult("Use of deprecated kubelet config flag feature-gates", target)}
	}

	kubeletConfig, err := kubeutils.GetKubeletConfig(ctx, nodePodExecutor, rawKubeletCommand)
	if err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), target)}
	}

	if kubeletConfig.FeatureGates == nil {
		kubeletConfig.FeatureGates = map[string]bool{}
	}

	if kubeletConfig.ServerTLSBootstrap == nil {
		return []rule.CheckResult{rule.WarningCheckResult("Option serverTLSBootstrap not set", target)}
	}
	if _, ok := kubeletConfig.FeatureGates["RotateKubeletServerCertificate"]; !ok {
		kubeletConfig.FeatureGates["RotateKubeletServerCertificate"] = true
	}

	// https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/#certificate-rotation
	if *kubeletConfig.ServerTLSBootstrap && kubeletConfig.FeatureGates["RotateKubeletServerCertificate"] {
		pkiServerStatsRaw, err := nodePodExecutor.Execute(ctx, "/bin/sh", `stat -Lc "%a %u %g %n" /var/lib/kubelet/pki/kubelet-server-*.pem`)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execNodePodTarget))
		}
		pkiServerStats := strings.Split(strings.TrimSpace(pkiServerStatsRaw), "\n")

		for _, pkiServerStat := range pkiServerStats {
			statSlice := strings.Split(pkiServerStat, " ")
			checkResults = append(checkResults, utils.MatchFilePermissionsAndOwnersCases(statSlice[0], statSlice[1], statSlice[2], strings.Join(statSlice[3:], " "),
				"600", expectedFileOwnerUsers, expectedFileOwnerGroups, target)...)
		}

	} else {
		pkiCRTStatsRaw, err := nodePodExecutor.Execute(ctx, "/bin/sh", `stat -Lc "%a %u %g %n" /var/lib/kubelet/pki/*.crt`)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execNodePodTarget))
		}
		pkiCrtStats := strings.Split(strings.TrimSpace(pkiCRTStatsRaw), "\n")

		for _, pkiCrtStat := range pkiCrtStats { // rule 242466
			statSlice := strings.Split(pkiCrtStat, " ")
			checkResults = append(checkResults, utils.MatchFilePermissionsAndOwnersCases(statSlice[0], statSlice[1], statSlice[2], strings.Join(statSlice[3:], " "),
				"644", expectedFileOwnerUsers, expectedFileOwnerGroups, target)...)
		}

		pkiKeyStatsRaw, err := nodePodExecutor.Execute(ctx, "/bin/sh", `stat -Lc "%a %u %g %n" /var/lib/kubelet/pki/*.key`)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execNodePodTarget))
		}
		pkiKeyStats := strings.Split(strings.TrimSpace(pkiKeyStatsRaw), "\n")
		for _, pkiServerStat := range pkiKeyStats { // rule 242467
			statSlice := strings.Split(pkiServerStat, " ")
			checkResults = append(checkResults, utils.MatchFilePermissionsAndOwnersCases(statSlice[0], statSlice[1], statSlice[2], strings.Join(statSlice[3:], " "),
				"600", expectedFileOwnerUsers, expectedFileOwnerGroups, target)...)
		}
	}
	return checkResults
}

func (r *RuleNodeFiles) getKubeletFlagValue(rawKubeletCommand, flag string) (string, error) {
	valueSlice := kubeutils.FindFlagValueRaw(strings.Split(rawKubeletCommand, " "), flag)

	if len(valueSlice) == 0 {
		return "", fmt.Errorf("kubelet %s flag has not been set", flag)
	}
	if len(valueSlice) > 1 {
		return "", fmt.Errorf("kubelet %s flag has been set more than once", flag)
	}
	return valueSlice[0], nil
}
