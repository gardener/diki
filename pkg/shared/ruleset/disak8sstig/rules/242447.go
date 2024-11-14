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
)

var (
	_ rule.Rule     = &Rule242447{}
	_ rule.Severity = &Rule242447{}
)

type Rule242447 struct {
	InstanceID string
	Client     client.Client
	PodContext pod.PodContext
	Options    *Options242447
	Logger     provider.Logger
}

type Options242447 struct {
	KubeProxyMatchLabels map[string]string `json:"kubeProxyMatchLabels" yaml:"kubeProxyMatchLabels"`
}

var _ option.Option = (*Options242447)(nil)

func (o Options242447) Validate() field.ErrorList {
	return validation.ValidateLabels(o.KubeProxyMatchLabels, field.NewPath("kubeProxyMatchLabels"))
}

func (r *Rule242447) ID() string {
	return ID242447
}

func (r *Rule242447) Name() string {
	return "The Kubernetes Kube Proxy kubeconfig must have file permissions set to 644 or more restrictive."
}

func (r *Rule242447) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242447) Run(ctx context.Context) (rule.RuleResult, error) {
	var checkResults []rule.CheckResult
	kubeProxySelector := labels.SelectorFromSet(labels.Set{"role": "proxy"})
	kubeProxyContainerNames := []string{"kube-proxy", "proxy"}

	if r.Options != nil && len(r.Options.KubeProxyMatchLabels) > 0 {
		kubeProxySelector = labels.SelectorFromSet(labels.Set(r.Options.KubeProxyMatchLabels))
	}

	target := rule.NewTarget()
	allPods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target.With("kind", "podList"))), nil
	}

	var pods []corev1.Pod
	for _, p := range allPods {
		if kubeProxySelector.Matches(labels.Set(p.Labels)) {
			pods = append(pods, p)
		}
	}

	if len(pods) == 0 {
		return rule.Result(r, rule.ErroredCheckResult("kube-proxy pods not found", target.With("selector", kubeProxySelector.String()))), nil
	}

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target.With("kind", "nodeList"))), nil
	}
	nodesAllocatablePods := kubeutils.GetNodesAllocatablePodsNum(allPods, nodes)
	groupedPods, checks := kubeutils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, target)
	checkResults = append(checkResults, checks...)
	image, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
	}
	image.WithOptionalTag(version.Get().GitVersion)

	for nodeName, pods := range groupedPods {
		podName := fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
		execPodTarget := target.With("name", podName, "namespace", "kube-system", "kind", "pod")

		defer func() {
			if err := r.PodContext.Delete(ctx, podName, "kube-system"); err != nil {
				r.Logger.Error(err.Error())
			}
		}()

		additionalLabels := map[string]string{pod.LabelInstanceID: r.InstanceID}
		podExecutor, err := r.PodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", image.String(), nodeName, additionalLabels))
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			continue
		}

		execPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: "kube-system",
			},
		}

		if err := r.Client.Get(ctx, client.ObjectKeyFromObject(execPod), execPod); err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			continue
		}

		execContainerID := execPod.Status.ContainerStatuses[0].ContainerID
		execBaseContainerID := strings.Split(execContainerID, "//")[1]
		execContainerPath := fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/k8s.io/%s/rootfs", execBaseContainerID)

		slices.SortFunc(pods, func(a, b corev1.Pod) int {
			return cmp.Compare(a.Name, b.Name)
		})

		for _, pod := range pods {
			var selectedFileStats []intutils.FileStats
			expectedFilePermissionsMax := "644"
			podTarget := target.With("name", pod.Name, "namespace", pod.Namespace, "kind", "pod")

			rawKubeProxyCommand, err := kubeutils.GetContainerCommand(pod, kubeProxyContainerNames...)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), podTarget))
				continue
			}

			kubeconfigPath, err := r.getKubeProxyFlagValue(rawKubeProxyCommand, "kubeconfig")
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), podTarget))
				continue
			}

			configPath, err := r.getKubeProxyFlagValue(rawKubeProxyCommand, "config")
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), podTarget))
				continue
			}

			kubeProxyContainerID, err := intutils.GetContainerID(pod, kubeProxyContainerNames...)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), podTarget))
				continue
			}

			kubeProxyMounts, err := intutils.GetContainerMounts(ctx, execContainerPath, podExecutor, kubeProxyContainerID)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
				continue
			}

			if len(configPath) != 0 {
				configSourcePath, err := kubeutils.FindFileMountSource(configPath, kubeProxyMounts)
				if err != nil {
					checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), podTarget))
					continue
				}

				configFileStats, err := intutils.GetSingleFileStats(ctx, podExecutor, configSourcePath)
				if err != nil {
					checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
					continue
				}

				selectedFileStats = append(selectedFileStats, configFileStats)

				// if the --kubeconfig path is not set then we read the configfile to get the kubeconfig
				// https://github.com/kubernetes/kubernetes/blob/2016fab3085562b4132e6d3774b6ded5ba9939fd/cmd/kube-proxy/app/server.go#L775
				if len(kubeconfigPath) == 0 {
					kubeProxyConfig, err := kubeutils.GetKubeProxyConfig(ctx, podExecutor, configSourcePath)
					if err != nil {
						checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
						continue
					}

					kubeconfigPath = kubeProxyConfig.ClientConnection.Kubeconfig
				}
			}

			if len(kubeconfigPath) == 0 {
				checkResults = append(checkResults, rule.PassedCheckResult("Kube-proxy uses in-cluster kubeconfig", podTarget))
				continue
			}

			kubeconfigSourcePath, err := kubeutils.FindFileMountSource(kubeconfigPath, kubeProxyMounts)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), podTarget))
				continue
			}

			kubeconfigFileStats, err := intutils.GetSingleFileStats(ctx, podExecutor, kubeconfigSourcePath)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
				continue
			}

			selectedFileStats = append(selectedFileStats, kubeconfigFileStats)

			for _, fileStats := range selectedFileStats {
				containerTarget := rule.NewTarget("name", pod.Name, "namespace", pod.Namespace, "kind", "pod")
				exceedFilePermissions, err := intutils.ExceedFilePermissions(fileStats.Permissions, expectedFilePermissionsMax)
				if err != nil {
					checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), containerTarget))
					continue
				}

				if exceedFilePermissions {
					detailedTarget := containerTarget.With("details", fmt.Sprintf("fileName: %s, permissions: %s, expectedPermissionsMax: %s", fileStats.Path, fileStats.Permissions, expectedFilePermissionsMax))
					checkResults = append(checkResults, rule.FailedCheckResult("File has too wide permissions", detailedTarget))
					continue
				}

				detailedTarget := containerTarget.With("details", fmt.Sprintf("fileName: %s, permissions: %s", fileStats.Path, fileStats.Permissions))
				checkResults = append(checkResults, rule.PassedCheckResult("File has expected permissions", detailedTarget))
			}
		}
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule242447) getKubeProxyFlagValue(rawCommand, flag string) (string, error) {
	valueSlice := kubeutils.FindFlagValueRaw(strings.Split(rawCommand, " "), flag)

	if len(valueSlice) == 0 {
		return "", nil
	}
	if len(valueSlice) > 1 {
		return "", fmt.Errorf("kube-proxy %s flag has been set more than once", flag)
	}
	return valueSlice[0], nil
}
