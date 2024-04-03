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
	"k8s.io/apimachinery/pkg/apis/meta/v1/validation"
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
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ rule.Rule = &Rule242451{}

type Rule242451 struct {
	InstanceID string
	Client     client.Client
	PodContext pod.PodContext
	Options    *Options242451
	Logger     provider.Logger
}

type Options242451 struct {
	KubeProxyMatchLabels map[string]string `json:"kubeProxyMatchLabels" yaml:"kubeProxyMatchLabels"`
	NodeGroupByLabels    []string          `json:"nodeGroupByLabels" yaml:"nodeGroupByLabels"`
	*option.FileOwnerOptions
}

var _ option.Option = (*Options242451)(nil)

func (o Options242451) Validate() field.ErrorList {
	allErrs := validation.ValidateLabels(o.KubeProxyMatchLabels, field.NewPath("kubeProxyMatchLabels"))
	allErrs = append(allErrs, option.ValidateLabelNames(o.NodeGroupByLabels, field.NewPath("nodeGroupByLabels"))...)
	if o.FileOwnerOptions != nil {
		return append(allErrs, o.FileOwnerOptions.Validate()...)
	}
	return allErrs
}

func (r *Rule242451) ID() string {
	return sharedv1r11.ID242451
}

func (r *Rule242451) Name() string {
	return "The Kubernetes component PKI must be owned by root (MEDIUM 242451)"
}

func (r *Rule242451) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults      []rule.CheckResult
		nodeLabels        []string
		pods              []corev1.Pod
		options           option.FileOwnerOptions
		kubeProxySelector = labels.SelectorFromSet(labels.Set{"role": "proxy"})
	)

	if r.Options != nil {
		if r.Options.FileOwnerOptions != nil {
			options = *r.Options.FileOwnerOptions
		}
		if len(r.Options.KubeProxyMatchLabels) > 0 {
			kubeProxySelector = labels.SelectorFromSet(labels.Set(r.Options.KubeProxyMatchLabels))
		}
		if r.Options.NodeGroupByLabels != nil {
			nodeLabels = slices.Clone(r.Options.NodeGroupByLabels)
		}
	}
	if len(options.ExpectedFileOwner.Users) == 0 {
		options.ExpectedFileOwner.Users = []string{"0"}
	}
	if len(options.ExpectedFileOwner.Groups) == 0 {
		options.ExpectedFileOwner.Groups = []string{"0"}
	}

	allPods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList"))), nil
	}

	for _, p := range allPods {
		if kubeProxySelector.Matches(labels.Set(p.Labels)) {
			pods = append(pods, p)
		}
	}

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}
	nodesAllocatablePods := kubeutils.GetNodesAllocatablePodsNum(allPods, nodes)

	image, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
	}
	image.WithOptionalTag(version.Get().GitVersion)

	if len(pods) == 0 {
		checkResults = append(checkResults, rule.FailedCheckResult("Pods not found!", rule.NewTarget("selector", kubeProxySelector.String())))
	} else {
		groupedShootPods, checks := kubeutils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, rule.NewTarget())
		checkResults = append(checkResults, checks...)

		for nodeName, pods := range groupedShootPods {
			checkResults = append(checkResults,
				r.checkPods(ctx, pods, nodeName, image.String(), options)...)
		}
	}

	selectedShootNodes, checks := kubeutils.SelectNodes(nodes, nodesAllocatablePods, nodeLabels)
	checkResults = append(checkResults, checks...)

	if len(selectedShootNodes) == 0 {
		checkResults = append(checkResults, rule.ErroredCheckResult("no allocatable nodes could be selected", rule.NewTarget()))
	}

	for _, node := range selectedShootNodes {
		checkResults = append(checkResults,
			r.checkKubelet(ctx, node.Name, image.String(), options)...)
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (r *Rule242451) checkPods(
	ctx context.Context,
	pods []corev1.Pod,
	nodeName, imageName string,
	options option.FileOwnerOptions,
) []rule.CheckResult {
	var (
		checkResults     []rule.CheckResult
		podName          = fmt.Sprintf("diki-%s-%s", r.ID(), sharedv1r11.Generator.Generate(10))
		execPodTarget    = rule.NewTarget("name", podName, "namespace", "kube-system", "kind", "pod")
		additionalLabels = map[string]string{pod.LabelInstanceID: r.InstanceID}
	)

	defer func() {
		if err := r.PodContext.Delete(ctx, podName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()

	podExecutor, err := r.PodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", imageName, nodeName, additionalLabels))
	if err != nil {
		return []rule.CheckResult{rule.ErroredCheckResult(err.Error(), execPodTarget)}
	}

	execPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: "kube-system",
		},
	}

	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(execPod), execPod); err != nil {
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
				containerTarget = rule.NewTarget("name", pod.Name, "namespace", pod.Namespace, "kind", "pod", "containerName", containerName)
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
	options option.FileOwnerOptions) []rule.CheckResult {
	var (
		delimiter         = "\t"
		checkResults      []rule.CheckResult
		selectedFileStats []intutils.FileStats
		pkiDirs           = map[string]struct{}{}
		podName           = fmt.Sprintf("diki-%s-%s", r.ID(), sharedv1r11.Generator.Generate(10))
		nodeTarget        = rule.NewTarget("name", nodeName, "kind", "node")
		execPodTarget     = rule.NewTarget("name", podName, "namespace", "kube-system", "kind", "pod")
		additionalLabels  = map[string]string{pod.LabelInstanceID: r.InstanceID}
	)

	defer func() {
		if err := r.PodContext.Delete(ctx, podName, "kube-system"); err != nil {
			r.Logger.Error(err.Error())
		}
	}()
	podExecutor, err := r.PodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", imageName, nodeName, additionalLabels))
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
