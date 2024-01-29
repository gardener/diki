// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/component-base/version"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/images"
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

	image, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
	}

	// check if tag is not present and use diki's version as a default
	if image.Tag == nil {
		tag := version.Get().GitVersion
		image.Tag = &tag
	}

	clusterNodes, err := kubeutils.GetNodes(ctx, r.ClusterClient, 512)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("cluster", "shoot", "kind", "nodeList"))), nil
	}

	clusterPods, err := kubeutils.GetPods(ctx, r.ClusterClient, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("cluster", "shoot", "kind", "podList"))), nil
	}

	clusterWorkers, err := utils.GetWorkers(ctx, r.ControlPlaneClient, r.ControlPlaneNamespace, 512)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("cluster", "seed", "kind", "workerList"))), nil
	}

	nodesAllocatablePodsNum := kubeutils.GetNodesAllocatablePodsNum(clusterPods, clusterNodes)
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
	kubeletFilePaths := []string{}

	runningNode := workerGroupNodes[workerGroup]
	target := rule.NewTarget("cluster", "shoot", "name", workerGroup, "kind", "workerGroup")
	if !runningNode.Allocatable {
		return []rule.CheckResult{rule.WarningCheckResult("There are no ready nodes with at least 1 allocatable spot for worker group.", target)}
	}

	nodePodName := fmt.Sprintf("diki-%s-%s", IDNodeFiles, Generator.Generate(10))
	execNodePodTarget := rule.NewTarget("cluster", "shoot", "name", nodePodName, "namespace", "kube-system", "kind", "pod")
	defer func() {
		if err := r.ClusterPodContext.Delete(ctx, nodePodName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()
	additionalLabels := map[string]string{
		pod.LabelInstanceID: r.InstanceID,
	}
	nodePodExecutor, err := r.ClusterPodContext.Create(
		ctx,
		pod.NewPrivilegedPod(nodePodName, "kube-system", image, runningNode.Node.Name, additionalLabels),
	)
	if err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execNodePodTarget)}
	}

	if kubeletServicePath, err := nodePodExecutor.Execute(ctx, "/bin/sh", "systemctl show -P FragmentPath kubelet.service"); err != nil {
		checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("could not find kubelet.service path: %s", err.Error()), execNodePodTarget))
	} else {
		kubeletFilePaths = append(kubeletFilePaths, kubeletServicePath) // rules 242406, 242407
	}

	rawKubeletCommand, err := kubeutils.GetKubeletCommand(ctx, nodePodExecutor)
	if err != nil {
		checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execNodePodTarget))
	}

	var kubeconfigPath string
	if len(rawKubeletCommand) > 0 {
		kubeletConfig, err := kubeutils.GetKubeletConfig(ctx, nodePodExecutor, rawKubeletCommand)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("could not retrieve kubelet config: %s", err.Error()), execNodePodTarget))
			goto kubeletFileChecks
		}

		switch {
		case kubeletConfig.Authentication.X509.ClientCAFile == nil:
			checkResults = append(checkResults, rule.FailedCheckResult("could not find client ca path: client-ca-file not set.", execNodePodTarget))
		case strings.TrimSpace(*kubeletConfig.Authentication.X509.ClientCAFile) == "":
			checkResults = append(checkResults, rule.FailedCheckResult("could not find client ca path: client-ca-file is empty.", execNodePodTarget))
		default:
			kubeletFilePaths = append(kubeletFilePaths, *kubeletConfig.Authentication.X509.ClientCAFile) // rules 242449, 242450
		}

		if kubeconfigPath, err = r.getKubeletFlagValue(rawKubeletCommand, "kubeconfig"); err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("could not find kubeconfig path: %s", err.Error()), execNodePodTarget))
		} else {
			kubeletFilePaths = append(kubeletFilePaths, kubeconfigPath) // not demanded, but similar in nature to rules 242452, 242453 and 242467
		}

		if kubeletConfigPath, err := r.getKubeletFlagValue(rawKubeletCommand, "config"); err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("could not find kubelet config path: %s", err.Error()), execNodePodTarget))
		} else {
			kubeletFilePaths = append(kubeletFilePaths, kubeletConfigPath) // rules 242452, 242453
		}

		if kubeletConfig.TLSPrivateKeyFile != nil && kubeletConfig.TLSCertFile != nil {
			tlsPrivateKeyFileDir := filepath.Dir(*kubeletConfig.TLSPrivateKeyFile)
			if len(*kubeletConfig.TLSPrivateKeyFile) == 0 {
				checkResults = append(checkResults, rule.FailedCheckResult("could not find private key file, option tlsPrivateKeyFile is empty.", target))
			} else {
				checkResults = append(checkResults, r.matchSingleFilePermissionsAndOwnersCases(ctx, nodePodExecutor, execNodePodTarget, target, tlsPrivateKeyFileDir,
					"755", expectedFileOwnerUsers, expectedFileOwnerGroups)...) // rule 242451
				checkResults = append(checkResults, r.matchSingleFilePermissionsAndOwnersCases(ctx, nodePodExecutor, execNodePodTarget, target, *kubeletConfig.TLSPrivateKeyFile,
					"600", expectedFileOwnerUsers, expectedFileOwnerGroups)...) // rule 242467
			}

			if len(*kubeletConfig.TLSCertFile) == 0 {
				checkResults = append(checkResults, rule.FailedCheckResult("could not find cert file, option tlsCertFile is empty.", target))
			} else {
				tlsCertFileDir := filepath.Dir(*kubeletConfig.TLSCertFile)
				if tlsCertFileDir != tlsPrivateKeyFileDir {
					checkResults = append(checkResults, r.matchSingleFilePermissionsAndOwnersCases(ctx, nodePodExecutor, execNodePodTarget, target, tlsCertFileDir,
						"755", expectedFileOwnerUsers, expectedFileOwnerGroups)...) // rule 242451
				}
				checkResults = append(checkResults, r.matchSingleFilePermissionsAndOwnersCases(ctx, nodePodExecutor, execNodePodTarget, target, *kubeletConfig.TLSCertFile,
					"644", expectedFileOwnerUsers, expectedFileOwnerGroups)...) // rule 242466
			}
		} else {
			// set kubeletPKIDir to default value https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/
			kubeletPKIDir := "/var/lib/kubelet/pki"
			if kubeutils.IsFlagSet(rawKubeletCommand, "cert-dir") {
				if kubeletPKIDir, err = r.getKubeletFlagValue(rawKubeletCommand, "cert-dir"); err != nil {
					checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("could not find kubelet cert-dir: %s", err.Error()), execNodePodTarget))
					goto kubeletFileChecks
				}
			}

			pkiAllStatsRaw, err := nodePodExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`find %s -exec stat -Lc "%%a %%u %%g %%F %%n" {} \;`, kubeletPKIDir)) // rule 242451
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execNodePodTarget))
				goto kubeletFileChecks
			} else if len(pkiAllStatsRaw) == 0 {
				checkResults = append(checkResults, rule.ErroredCheckResult("Stats not found", target.With("details", fmt.Sprintf("filePath: %s", kubeletPKIDir))))
				goto kubeletFileChecks
			}

			pkiAllStats := strings.Split(strings.TrimSpace(pkiAllStatsRaw), "\n")
			privateKeyChecked := false
			for _, pkiAllStat := range pkiAllStats {
				pkiAllStatSlice := strings.Split(pkiAllStat, " ")
				fileType := pkiAllStatSlice[3]
				var fileName string

				// the file type %F can have " " characters. Ex: "regular file"
				for i := 4; i < len(pkiAllStatSlice); i++ {
					if strings.HasPrefix(pkiAllStatSlice[i], kubeletPKIDir) {
						fileName = strings.Join(pkiAllStatSlice[i:], " ")
						break
					}
					fileType = fmt.Sprintf("%s %s", fileType, pkiAllStatSlice[i])
				}

				switch {
				case strings.HasSuffix(fileName, ".key") || strings.HasSuffix(fileName, ".pem"): // rule 242467
					privateKeyChecked = true
					checkResults = append(checkResults, utils.MatchFilePermissionsAndOwnersCases(pkiAllStatSlice[0], pkiAllStatSlice[1], pkiAllStatSlice[2], fileName,
						"600", expectedFileOwnerUsers, expectedFileOwnerGroups, target)...)
				case strings.HasSuffix(fileName, ".crt"): // rule 242466
					checkResults = append(checkResults, utils.MatchFilePermissionsAndOwnersCases(pkiAllStatSlice[0], pkiAllStatSlice[1], pkiAllStatSlice[2], fileName,
						"644", expectedFileOwnerUsers, expectedFileOwnerGroups, target)...)
				case fileType == "directory": // rule 242451
					checkResults = append(checkResults, utils.MatchFileOwnersCases(pkiAllStatSlice[1], pkiAllStatSlice[2], fileName,
						expectedFileOwnerUsers, expectedFileOwnerGroups, target)...)
				default:
					checkResults = append(checkResults, utils.MatchFilePermissionsAndOwnersCases(pkiAllStatSlice[0], pkiAllStatSlice[1], pkiAllStatSlice[2], fileName,
						"644", expectedFileOwnerUsers, expectedFileOwnerGroups, target)...)
				}
			}
			if !privateKeyChecked {
				checkResults = append(checkResults, rule.FailedCheckResult("could not find private key files in kubelet cert-dir", target.With("details", fmt.Sprintf("filePath: %s", kubeletPKIDir))))
			}
		}
	} else {
		checkResults = append(checkResults, rule.ErroredCheckResult("could not retrieve kubelet config: kubelet command not retrived", execNodePodTarget),
			rule.ErroredCheckResult("could not find kubeconfig path: kubelet command not retrived", execNodePodTarget))
	}

kubeletFileChecks:
	for _, kubeletFilePath := range kubeletFilePaths {
		target := target.With("details", fmt.Sprintf("filePath: %s", kubeletFilePath))
		expectedFilePermissionsMax := "644"
		if kubeletFilePath == kubeconfigPath {
			expectedFilePermissionsMax = "600"
		}

		checkResults = append(checkResults, r.matchSingleFilePermissionsAndOwnersCases(ctx, nodePodExecutor, execNodePodTarget, target, kubeletFilePath,
			expectedFilePermissionsMax, expectedFileOwnerUsers, expectedFileOwnerGroups)...)
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

func (r *RuleNodeFiles) matchSingleFilePermissionsAndOwnersCases(
	ctx context.Context,
	nodePodExecutor pod.PodExecutor,
	execNodePodTarget, fileTarget rule.Target,
	filePath, expectedFilePermissionsMax string,
	expectedFileOwnerUsers, expectedFileOwnerGroups []string) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
	statsRaw, err := nodePodExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`stat -Lc "%%a %%u %%g %%n" %s`, filePath))
	if err != nil {
		checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execNodePodTarget))
		return checkResults
	}
	if len(statsRaw) == 0 {
		checkResults = append(checkResults, rule.ErroredCheckResult("Stats not found", fileTarget))
		return checkResults
	}
	stat := strings.Split(strings.TrimSpace(statsRaw), "\n")[0]

	statSlice := strings.Split(stat, " ")
	checkResults = append(checkResults, utils.MatchFilePermissionsAndOwnersCases(statSlice[0], statSlice[1], statSlice[2], strings.Join(statSlice[3:], " "),
		expectedFilePermissionsMax, expectedFileOwnerUsers, expectedFileOwnerGroups, fileTarget)...)

	return checkResults
}
