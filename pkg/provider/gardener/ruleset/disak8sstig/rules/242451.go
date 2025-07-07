// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
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
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var (
	_ rule.Rule     = &Rule242451{}
	_ rule.Severity = &Rule242451{}
)

type Rule242451 struct {
	InstanceID             string
	ControlPlaneClient     client.Client
	ClusterClient          client.Client
	ControlPlaneNamespace  string
	ControlPlanePodContext pod.PodContext
	ClusterPodContext      pod.PodContext
	Options                *Options242451
	Logger                 provider.Logger
}

type Options242451 struct {
	option.KubeProxyOptions
	*option.FileOwnerOptions
}

var _ option.Option = (*Options242451)(nil)

func (o Options242451) Validate() field.ErrorList {
	if o.FileOwnerOptions != nil {
		return o.FileOwnerOptions.Validate()
	}
	return nil
}

func (r *Rule242451) ID() string {
	return sharedrules.ID242451
}

func (r *Rule242451) Name() string {
	return "The Kubernetes component PKI must be owned by root."
}

func (r *Rule242451) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242451) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults     []rule.CheckResult
		fileOwnerOptions option.FileOwnerOptions
		// TODO: Drop support for "instance" etcd label in a future release
		// "instance" label is no longer in use for etcd-druid versions >= v0.23. ref: https://github.com/gardener/etcd-druid/pull/777
		etcdMainOldSelector = labels.SelectorFromSet(labels.Set{"instance": "etcd-main"})
		etcdMainSelector    = labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": "etcd-main"})
		// TODO: Drop support for "instance" etcd label in a future release
		// "instance" label is no longer in use for etcd-druid versions >= v0.23. ref: https://github.com/gardener/etcd-druid/pull/777
		etcdEventsOldSelector = labels.SelectorFromSet(labels.Set{"instance": "etcd-events"})
		etcdEventsSelector    = labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": "etcd-events"})
		kubeProxySelector     = labels.SelectorFromSet(labels.Set{"role": "proxy"})
		deploymentNames       = []string{"kube-apiserver", "kube-controller-manager", "kube-scheduler"}
		nodeLabels            = []string{"worker.gardener.cloud/pool"}
	)

	if r.Options != nil && r.Options.FileOwnerOptions != nil {
		fileOwnerOptions = *r.Options.FileOwnerOptions
	}
	if len(fileOwnerOptions.ExpectedFileOwner.Users) == 0 {
		fileOwnerOptions.ExpectedFileOwner.Users = []string{"0"}
	}
	if len(fileOwnerOptions.ExpectedFileOwner.Groups) == 0 {
		fileOwnerOptions.ExpectedFileOwner.Groups = []string{"0"}
	}

	image, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
	}
	image.WithOptionalTag(version.Get().GitVersion)

	// control plane check
	seedTarget := rule.NewTarget("cluster", "seed")
	allSeedPods, err := kubeutils.GetPods(ctx, r.ControlPlaneClient, "", labels.NewSelector(), 300)
	if err != nil {
		checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), seedTarget.With("namespace", r.ControlPlaneNamespace, "kind", "PodList")))
	} else {
		var (
			checkPods               []corev1.Pod
			podOldSelectors         = []labels.Selector{etcdMainOldSelector, etcdEventsOldSelector}
			podSelectors            = []labels.Selector{etcdMainSelector, etcdEventsSelector}
			oldSelectorCheckResults []rule.CheckResult
		)

		seedReplicaSets, err := kubeutils.GetReplicaSets(ctx, r.ControlPlaneClient, "", labels.NewSelector(), 300)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), seedTarget.With("namespace", r.ControlPlaneNamespace, "kind", "ReplicaSetList")))
		}

		filteredSeedPods := kubeutils.FilterPodsByOwnerRef(allSeedPods)

		for _, podSelector := range podOldSelectors {
			var pods []corev1.Pod
			for _, p := range filteredSeedPods {
				if podSelector.Matches(labels.Set(p.Labels)) && p.Namespace == r.ControlPlaneNamespace {
					pods = append(pods, p)
				}
			}

			if len(pods) == 0 {
				oldSelectorCheckResults = append(oldSelectorCheckResults, rule.ErroredCheckResult("pods not found", seedTarget.With("namespace", r.ControlPlaneNamespace, "selector", podSelector.String())))
				continue
			}

			checkPods = append(checkPods, pods...)
		}

		if len(checkPods) == 0 {
			for _, podSelector := range podSelectors {
				var pods []corev1.Pod
				for _, p := range filteredSeedPods {
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
		} else {
			checkResults = append(checkResults, oldSelectorCheckResults...)
		}

		for _, deploymentName := range deploymentNames {
			pods, err := kubeutils.GetDeploymentPods(ctx, r.ControlPlaneClient, deploymentName, r.ControlPlaneNamespace)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), seedTarget.With("kind", "PodList")))
				continue
			}

			filteredPods := kubeutils.FilterPodsByOwnerRef(pods)

			if len(pods) == 0 {
				checkResults = append(checkResults, rule.ErroredCheckResult("pods not found for deployment", seedTarget.With("name", deploymentName, "kind", "Deployment", "namespace", r.ControlPlaneNamespace)))
				continue
			}

			checkPods = append(checkPods, filteredPods...)
		}

		if len(checkPods) > 0 {
			nodes, err := kubeutils.GetNodes(ctx, r.ControlPlaneClient, 300)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), seedTarget.With("kind", "NodeList")))
			} else {
				nodesAllocatablePods := kubeutils.GetNodesAllocatablePodsNum(allSeedPods, nodes)
				groupedPods, checks := kubeutils.SelectPodOfReferenceGroup(checkPods, nodesAllocatablePods, seedTarget)
				checkResults = append(checkResults, checks...)

				for nodeName, pods := range groupedPods {
					checkResults = append(checkResults,
						r.checkPods(ctx, r.ControlPlaneClient, r.ControlPlanePodContext, pods, seedReplicaSets, nodeName, image.String(), fileOwnerOptions, seedTarget)...)
				}
			}
		}
	}

	shootTarget := rule.NewTarget("cluster", "shoot")
	allShootPods, err := kubeutils.GetPods(ctx, r.ClusterClient, "", labels.NewSelector(), 300)
	if err != nil {
		checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "PodList")))
		return rule.Result(r, checkResults...), nil
	}

	filteredShootPods := kubeutils.FilterPodsByOwnerRef(allShootPods)

	shootReplicaSets, err := kubeutils.GetReplicaSets(ctx, r.ClusterClient, "", labels.NewSelector(), 300)
	if err != nil {
		checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "ReplicaSetList")))
	}

	shootNodes, err := kubeutils.GetNodes(ctx, r.ClusterClient, 300)
	if err != nil {
		checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), shootTarget.With("kind", "NodeList")))
		return rule.Result(r, checkResults...), nil
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
			r.checkKubelet(ctx, node.Name, image.String(), fileOwnerOptions, shootTarget)...)
	}

	// kube-proxy check
	if r.Options != nil && r.Options.KubeProxyDisabled {
		checkResults = append(checkResults, rule.AcceptedCheckResult("kube-proxy check is skipped.", shootTarget))
		return rule.Result(r, checkResults...), nil
	}

	var pods []corev1.Pod
	for _, p := range filteredShootPods {
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
				r.checkPods(ctx, r.ClusterClient, r.ClusterPodContext, pods, shootReplicaSets, nodeName, image.String(), fileOwnerOptions, shootTarget)...)
		}
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule242451) checkPods(
	ctx context.Context,
	c client.Client,
	pc pod.PodContext,
	pods []corev1.Pod,
	replicaSets []appsv1.ReplicaSet,
	nodeName, imageName string,
	options option.FileOwnerOptions,
	target rule.Target) []rule.CheckResult {
	var (
		checkResults     []rule.CheckResult
		podName          = fmt.Sprintf("diki-%s-%s", r.ID(), sharedrules.Generator.Generate(10))
		execPodTarget    = target.With("name", podName, "namespace", "kube-system", "kind", "Pod")
		additionalLabels = map[string]string{pod.LabelInstanceID: r.InstanceID}
	)

	defer func() {
		timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()

		if err := pc.Delete(timeoutCtx, podName, "kube-system"); err != nil {
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
			var (
				delimiter       = "\t"
				pkiDirs         = map[string]struct{}{}
				containerTarget = kubeutils.TargetWithPod(target.With("containerName", containerName), pod, replicaSets)
			)

			// We iterate through a files matching certain suffixes and we check their permissions
			// Directories that contain such files are saved so that they can be checked in the following for cycle
			for _, fileStat := range fileStats {
				if !strings.HasSuffix(fileStat.Path, ".key") && !strings.HasSuffix(fileStat.Path, ".pem") && !strings.HasSuffix(fileStat.Path, ".crt") {
					continue
				}

				pkiDirs[fileStat.Dir()] = struct{}{}

				checkResults = append(checkResults, intutils.MatchFileOwnersCases(fileStat, options.ExpectedFileOwner.Users, options.ExpectedFileOwner.Groups, containerTarget)...)
			}

			for dir := range pkiDirs {
				dirStats, err := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`stat -Lc "%%a%[1]s%%u%[1]s%%g%[1]s%%F%[1]s%%n" %s`, delimiter, dir))
				if err != nil {
					checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
					continue
				}

				if len(dirStats) == 0 {
					checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("could not find file %s", dir), execPodTarget))
					continue
				}

				dirFilesStats := strings.Split(strings.TrimSpace(dirStats), "\n")
				dirFileStats, err := intutils.NewFileStats(dirFilesStats[0], delimiter)
				if err != nil {
					checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
					continue
				}

				checkResults = append(checkResults, intutils.MatchFileOwnersCases(dirFileStats, options.ExpectedFileOwner.Users, options.ExpectedFileOwner.Groups, containerTarget)...)
			}
		}
	}
	return checkResults
}

func (r *Rule242451) checkKubelet(
	ctx context.Context,
	nodeName, imageName string,
	options option.FileOwnerOptions,
	target rule.Target) []rule.CheckResult {
	var (
		checkResults      []rule.CheckResult
		selectedFileStats []intutils.FileStats
		pkiDirs           = map[string]struct{}{}
		podName           = fmt.Sprintf("diki-%s-%s", r.ID(), sharedrules.Generator.Generate(10))
		nodeTarget        = target.With("name", nodeName, "kind", "Node")
		execPodTarget     = target.With("name", podName, "namespace", "kube-system", "kind", "Pod")
		additionalLabels  = map[string]string{pod.LabelInstanceID: r.InstanceID}
	)

	defer func() {
		timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()

		if err := r.ClusterPodContext.Delete(timeoutCtx, podName, "kube-system"); err != nil {
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
		if len(*kubeletConfig.TLSPrivateKeyFile) == 0 {
			checkResults = append(checkResults, rule.FailedCheckResult("could not find key file, option tlsPrivateKeyFile is empty.", nodeTarget))
		} else {
			keyFileStats, err := intutils.GetSingleFileStats(ctx, podExecutor, *kubeletConfig.TLSPrivateKeyFile)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			}
			selectedFileStats = append(selectedFileStats, keyFileStats)
		}
		if len(*kubeletConfig.TLSCertFile) == 0 {
			checkResults = append(checkResults, rule.FailedCheckResult("could not find cert file, option tlsCertFile is empty.", nodeTarget))
		} else {
			certFileStats, err := intutils.GetSingleFileStats(ctx, podExecutor, *kubeletConfig.TLSCertFile)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
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

		var selectedFilesStats []intutils.FileStats
		for _, pkiFileStat := range pkiFilesStats {
			if strings.HasSuffix(pkiFileStat.Path, ".crt") || strings.HasSuffix(pkiFileStat.Path, ".pem") || strings.HasSuffix(pkiFileStat.Path, ".key") {
				selectedFilesStats = append(selectedFilesStats, pkiFileStat)
			}
		}

		if len(selectedFilesStats) == 0 {
			return []rule.CheckResult{rule.ErroredCheckResult("no cert nor key files found in PKI directory", nodeTarget.With("directory", kubeletPKIDir))}
		}

		selectedFileStats = append(selectedFileStats, selectedFilesStats...)
	}

	for _, fileStats := range selectedFileStats {
		pkiDirs[fileStats.Dir()] = struct{}{}

		checkResults = append(checkResults, intutils.MatchFileOwnersCases(fileStats, options.ExpectedFileOwner.Users, options.ExpectedFileOwner.Groups, nodeTarget)...)
	}

	for dir := range pkiDirs {
		delimiter := "\t"
		dirStats, err := podExecutor.Execute(ctx, "/bin/sh", fmt.Sprintf(`stat -Lc "%%a%[1]s%%u%[1]s%%g%[1]s%%F%[1]s%%n" %s`, delimiter, dir))

		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			continue
		}

		if len(dirStats) == 0 {
			checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("could not find file %s", dir), execPodTarget))
			continue
		}

		dirFilesStats := strings.Split(strings.TrimSpace(dirStats), "\n")
		dirFileStats, err := intutils.NewFileStats(dirFilesStats[0], delimiter)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			continue
		}

		checkResults = append(checkResults, intutils.MatchFileOwnersCases(dirFileStats, options.ExpectedFileOwner.Users, options.ExpectedFileOwner.Groups, nodeTarget)...)
	}
	return checkResults
}
