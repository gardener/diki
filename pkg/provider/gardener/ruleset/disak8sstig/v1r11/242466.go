// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/component-base/version"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	intutils "github.com/gardener/diki/pkg/internal/utils"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/images"
	"github.com/gardener/diki/pkg/shared/provider"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ rule.Rule = &Rule242466{}

type Rule242466 struct {
	InstanceID             string
	ControlPlaneClient     client.Client
	ClusterClient          client.Client
	ControlPlaneNamespace  string
	ControlPlanePodContext pod.PodContext
	ClusterPodContext      pod.PodContext
	Options                *option.KubeProxyOptions
	Logger                 provider.Logger
}

func (r *Rule242466) ID() string {
	return sharedv1r11.ID242466
}

func (r *Rule242466) Name() string {
	return "The Kubernetes PKI CRT must have file permissions set to 644 or more restrictive (MEDIUM 242466)"
}

func (r *Rule242466) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults               []rule.CheckResult
		expectedFilePermissionsMax = "644"
		etcdMainSelector           = labels.SelectorFromSet(labels.Set{"instance": "etcd-main"})
		etcdEventsSelector         = labels.SelectorFromSet(labels.Set{"instance": "etcd-events"})
		kubeProxySelector          = labels.SelectorFromSet(labels.Set{"role": "proxy"})
		deploymentNames            = []string{"kube-apiserver", "kube-controller-manager", "kube-scheduler"}
		nodeLabels                 = []string{"worker.gardener.cloud/pool"}
	)

	image, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
	}
	image.WithOptionalTag(version.Get().GitVersion)

	// control plane check
	seedTarget := rule.NewTarget("cluster", "seed")
	allSeedPods, err := kubeutils.GetPods(ctx, r.ControlPlaneClient, "", labels.NewSelector(), 300)
	if err != nil {
		checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), seedTarget.With("namespace", r.ControlPlaneNamespace, "kind", "podList")))
	} else {
		var (
			checkPods    []corev1.Pod
			podSelectors = []labels.Selector{etcdMainSelector, etcdEventsSelector}
		)

		for _, podSelector := range podSelectors {
			var pods []corev1.Pod
			for _, p := range allSeedPods {
				if podSelector.Matches(labels.Set(p.Labels)) && p.Namespace == r.ControlPlaneNamespace {
					pods = append(pods, p)
				}
			}

			if len(pods) == 0 {
				checkResults = append(checkResults, rule.ErroredCheckResult("pods not found", seedTarget.With("namespace", r.ControlPlaneNamespace, "selector", podSelector.String())))
				continue
			}

			checkPods = append(checkPods, pods...)
		}

		for _, deploymentName := range deploymentNames {
			pods, err := kubeutils.GetDeploymentPods(ctx, r.ControlPlaneClient, deploymentName, r.ControlPlaneNamespace)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), seedTarget.With("kind", "podList")))
				continue
			}

			if len(pods) == 0 {
				checkResults = append(checkResults, rule.ErroredCheckResult("pods not found for deployment", seedTarget.With("name", deploymentName, "kind", "Deployment", "namespace", r.ControlPlaneNamespace)))
				continue
			}

			checkPods = append(checkPods, pods...)
		}

		if len(checkPods) > 0 {
			nodes, err := kubeutils.GetNodes(ctx, r.ControlPlaneClient, 300)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), seedTarget.With("kind", "nodeList")))
			} else {
				nodesAllocatablePods := kubeutils.GetNodesAllocatablePodsNum(allSeedPods, nodes)
				groupedPods, checks := kubeutils.SelectPodOfReferenceGroup(checkPods, nodesAllocatablePods, seedTarget)
				checkResults = append(checkResults, checks...)

				for nodeName, pods := range groupedPods {
					checkResults = append(checkResults,
						r.checkPods(ctx, r.ControlPlaneClient, r.ControlPlanePodContext, pods, nodeName, image.String(), expectedFilePermissionsMax, seedTarget)...)
				}
			}
		}
	}

	shootTarget := rule.NewTarget("cluster", "shoot")
	allShootPods, err := kubeutils.GetPods(ctx, r.ClusterClient, "", labels.NewSelector(), 300)
	if err != nil {
		checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "podList")))
		return rule.RuleResult{
			RuleID:       r.ID(),
			RuleName:     r.Name(),
			CheckResults: checkResults,
		}, nil
	}

	shootNodes, err := kubeutils.GetNodes(ctx, r.ClusterClient, 300)
	if err != nil {
		checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "nodeList")))
		return rule.RuleResult{
			RuleID:       r.ID(),
			RuleName:     r.Name(),
			CheckResults: checkResults,
		}, nil
	}
	shootNodesAllocatablePods := kubeutils.GetNodesAllocatablePodsNum(allShootPods, shootNodes)

	// kubelet check
	selectedShootNodes, checks := kubeutils.SelectNodes(shootNodes, shootNodesAllocatablePods, nodeLabels)
	checkResults = append(checkResults, checks...)

	if len(selectedShootNodes) == 0 {
		checkResults = append(checkResults, rule.ErroredCheckResult("no allocatable nodes could be selected", shootTarget))
	}

	for _, node := range selectedShootNodes {
		checkResults = append(checkResults,
			r.checkKubelet(ctx, node.Name, image.String(), expectedFilePermissionsMax, shootTarget)...)
	}

	// kube-proxy check
	if r.Options != nil && r.Options.KubeProxyDisabled {
		checkResults = append(checkResults, rule.AcceptedCheckResult("Kube-proxy is disabled for cluster", shootTarget))
		return rule.RuleResult{
			RuleID:       r.ID(),
			RuleName:     r.Name(),
			CheckResults: checkResults,
		}, nil
	}

	var pods []corev1.Pod
	for _, p := range allShootPods {
		if kubeProxySelector.Matches(labels.Set(p.Labels)) {
			pods = append(pods, p)
		}
	}

	if len(pods) == 0 {
		checkResults = append(checkResults, rule.ErroredCheckResult("pods not found", shootTarget.With("selector", kubeProxySelector.String())))
	} else {
		groupedShootPods, checks := kubeutils.SelectPodOfReferenceGroup(pods, shootNodesAllocatablePods, shootTarget)
		checkResults = append(checkResults, checks...)

		for nodeName, pods := range groupedShootPods {
			checkResults = append(checkResults,
				r.checkPods(ctx, r.ClusterClient, r.ClusterPodContext, pods, nodeName, image.String(), expectedFilePermissionsMax, shootTarget)...)
		}
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (r *Rule242466) checkPods(
	ctx context.Context,
	c client.Client,
	pc pod.PodContext,
	pods []corev1.Pod,
	nodeName, imageName string,
	expectedFilePermissionsMax string,
	target rule.Target) []rule.CheckResult {
	var (
		checkResults     []rule.CheckResult
		podName          = fmt.Sprintf("diki-%s-%s", r.ID(), sharedv1r11.Generator.Generate(10))
		execPodTarget    = target.With("name", podName, "namespace", "kube-system", "kind", "pod")
		additionalLabels = map[string]string{pod.LabelInstanceID: r.InstanceID}
	)

	defer func() {
		if err := pc.Delete(ctx, podName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()

	podExecutor, err := pc.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", imageName, nodeName, additionalLabels))
	if err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execPodTarget)}
	}

	execPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: "kube-system",
		},
	}

	if err := c.Get(ctx, client.ObjectKeyFromObject(execPod), execPod); err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execPodTarget)}
	}

	var (
		execContainerID     = execPod.Status.ContainerStatuses[0].ContainerID
		execBaseContainerID = strings.Split(execContainerID, "//")[1]
		execContainerPath   = fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/k8s.io/%s/rootfs", execBaseContainerID)
	)

	slices.SortFunc(pods, func(a, b corev1.Pod) int {
		return cmp.Compare(a.Name, b.Name)
	})

	for _, pod := range pods {
		excludedSources := []string{"/lib/modules", "/usr/share/ca-certificates", "/var/log/journal", "/var/run/dbus/system_bus_socket"}
		mappedFileStats, err := intutils.GetMountedFilesStats(ctx, execContainerPath, podExecutor, pod, excludedSources)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
		}

		for containerName, fileStats := range mappedFileStats {
			for _, fileStat := range fileStats {
				if !strings.HasSuffix(fileStat.Path, ".crt") && !strings.HasSuffix(fileStat.Path, ".pem") {
					continue
				}

				containerTarget := target.With("name", pod.Name, "namespace", pod.Namespace, "kind", "pod", "containerName", containerName)
				exceedFilePermissions, err := intutils.ExceedFilePermissions(fileStat.Permissions, expectedFilePermissionsMax)
				if err != nil {
					checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), containerTarget))
					continue
				}

				if exceedFilePermissions {
					detailedTarget := containerTarget.With("details", fmt.Sprintf("fileName: %s, permissions: %s, expectedPermissionsMax: %s", fileStat.Path, fileStat.Permissions, expectedFilePermissionsMax))
					checkResults = append(checkResults, rule.FailedCheckResult("File has too wide permissions", detailedTarget))
					continue
				}

				detailedTarget := containerTarget.With("details", fmt.Sprintf("fileName: %s, permissions: %s", fileStat.Path, fileStat.Permissions))
				checkResults = append(checkResults, rule.PassedCheckResult("File has expected permissions", detailedTarget))
			}
		}
	}
	return checkResults
}

func (r *Rule242466) checkKubelet(
	ctx context.Context,
	nodeName, imageName string,
	expectedFilePermissionsMax string,
	target rule.Target) []rule.CheckResult {
	var (
		checkResults      []rule.CheckResult
		selectedFileStats []intutils.FileStats
		podName           = fmt.Sprintf("diki-%s-%s", r.ID(), sharedv1r11.Generator.Generate(10))
		nodeTarget        = target.With("name", nodeName, "kind", "node")
		execPodTarget     = target.With("name", podName, "namespace", "kube-system", "kind", "pod")
		additionalLabels  = map[string]string{pod.LabelInstanceID: r.InstanceID}
	)

	defer func() {
		if err := r.ClusterPodContext.Delete(ctx, podName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()
	podExecutor, err := r.ClusterPodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", imageName, nodeName, additionalLabels))
	if err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execPodTarget)}
	}

	rawKubeletCommand, err := kubeutils.GetKubeletCommand(ctx, podExecutor)
	if err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execPodTarget)}
	}

	if len(rawKubeletCommand) == 0 {
		return []rule.CheckResult{rule.ErroredCheckResult("could not retrieve kubelet config: kubelet command not retrived", execPodTarget)}
	}

	kubeletConfig, err := kubeutils.GetKubeletConfig(ctx, podExecutor, rawKubeletCommand)
	if err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(fmt.Sprintf("could not retrieve kubelet config: %s", err.Error()), execPodTarget)}
	}

	if kubeletConfig.TLSPrivateKeyFile != nil && kubeletConfig.TLSCertFile != nil {
		if len(*kubeletConfig.TLSCertFile) == 0 {
			return []rule.CheckResult{rule.FailedCheckResult("could not find cert file, option tlsCertFile is empty.", nodeTarget)}
		} else {
			certFileStats, err := intutils.GetSingleFileStats(ctx, podExecutor, *kubeletConfig.TLSCertFile)
			if err != nil {
				return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execPodTarget)}
			}
			selectedFileStats = append(selectedFileStats, certFileStats)
		}
	} else {
		kubeletPKIDir := "/var/lib/kubelet/pki"
		if kubeutils.IsFlagSet(rawKubeletCommand, "cert-dir") {
			valueSlice := kubeutils.FindFlagValueRaw(strings.Split(rawKubeletCommand, " "), "cert-dir")
			if len(valueSlice) > 1 {
				return []rule.CheckResult{rule.ErroredCheckResult("kubelet cert-dir flag has been set more than once", execPodTarget)}
			}
			kubeletPKIDir = strings.TrimSpace(valueSlice[0])
			if len(kubeletPKIDir) == 0 {
				return []rule.CheckResult{rule.ErroredCheckResult("kubelet cert-dir flag set to empty", execPodTarget)}
			}
		}
		pkiFilesStats, err := intutils.GetFileStatsByDir(ctx, podExecutor, kubeletPKIDir)
		if err != nil {
			return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execPodTarget)}
		}

		var certFilesStats []intutils.FileStats
		for _, pkiFileStat := range pkiFilesStats {
			if strings.HasSuffix(pkiFileStat.Path, ".crt") || strings.HasSuffix(pkiFileStat.Path, ".pem") {
				certFilesStats = append(certFilesStats, pkiFileStat)
			}
		}

		if len(certFilesStats) == 0 {
			return []rule.CheckResult{rule.ErroredCheckResult("no '.crt' files found in PKI directory", nodeTarget.With("directory", kubeletPKIDir))}
		}

		selectedFileStats = append(selectedFileStats, certFilesStats...)
	}

	for _, fileStats := range selectedFileStats {
		exceedFilePermissions, err := intutils.ExceedFilePermissions(fileStats.Permissions, expectedFilePermissionsMax)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), nodeTarget))
			continue
		}

		if exceedFilePermissions {
			detailedTarget := nodeTarget.With("details", fmt.Sprintf("fileName: %s, permissions: %s, expectedPermissionsMax: %s", fileStats.Path, fileStats.Permissions, expectedFilePermissionsMax))
			checkResults = append(checkResults, rule.FailedCheckResult("File has too wide permissions", detailedTarget))
			continue
		}

		detailedTarget := nodeTarget.With("details", fmt.Sprintf("fileName: %s, permissions: %s", fileStats.Path, fileStats.Permissions))
		checkResults = append(checkResults, rule.PassedCheckResult("File has expected permissions", detailedTarget))
	}
	return checkResults
}
