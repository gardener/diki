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
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ rule.Rule = &Rule242466{}

type Rule242466 struct {
	InstanceID         string
	Client             client.Client
	Namespace          string
	PodContext         pod.PodContext
	ETCDMainSelector   labels.Selector
	ETCDEventsSelector labels.Selector
	DeploymentNames    []string
	Logger             provider.Logger
}

func (r *Rule242466) ID() string {
	return sharedv1r11.ID242466
}

func (r *Rule242466) Name() string {
	return "The Kubernetes PKI CRT must have file permissions set to 644 or more restrictive (MEDIUM 242466)"
}

func (r *Rule242466) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults       []rule.CheckResult
		etcdMainSelector   = labels.SelectorFromSet(labels.Set{"instance": "etcd-main"})
		etcdEventsSelector = labels.SelectorFromSet(labels.Set{"instance": "etcd-events"})
		deploymentNames    = []string{"kube-apiserver", "kube-controller-manager", "kube-scheduler"}
	)

	if r.ETCDMainSelector != nil {
		etcdMainSelector = r.ETCDMainSelector
	}

	if r.ETCDEventsSelector != nil {
		etcdEventsSelector = r.ETCDEventsSelector
	}

	if r.DeploymentNames != nil {
		deploymentNames = r.DeploymentNames
	}

	allPods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("namespace", r.Namespace, "kind", "podList"))), nil
	}
	podSelectors := []labels.Selector{etcdMainSelector, etcdEventsSelector}
	checkPods := []corev1.Pod{}

	for _, podSelector := range podSelectors {
		pods := []corev1.Pod{}
		for _, p := range allPods {
			if podSelector.Matches(labels.Set(p.Labels)) && p.Namespace == r.Namespace {
				pods = append(pods, p)
			}
		}

		if len(pods) == 0 {
			checkResults = append(checkResults, rule.FailedCheckResult("Pods not found!", rule.NewTarget("namespace", r.Namespace, "selector", podSelector.String())))
			continue
		}

		checkPods = append(checkPods, pods...)
	}

	for _, deploymentName := range deploymentNames {
		pods, err := kubeutils.GetDeploymentPods(ctx, r.Client, deploymentName, r.Namespace)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList")))
			continue
		}

		if len(pods) == 0 {
			checkResults = append(checkResults, rule.FailedCheckResult("Pods not found for deployment!", rule.NewTarget("name", deploymentName, "kind", "Deployment", "namespace", r.Namespace)))
			continue
		}

		checkPods = append(checkPods, pods...)
	}

	if len(checkPods) == 0 {
		return rule.RuleResult{
			RuleID:       r.ID(),
			RuleName:     r.Name(),
			CheckResults: checkResults,
		}, nil
	}

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
	}
	nodesAllocatablePods := kubeutils.GetNodesAllocatablePodsNum(allPods, nodes)
	groupedPods, checks := kubeutils.SelectPodOfReferenceGroup(checkPods, nodesAllocatablePods, rule.NewTarget())
	checkResults = append(checkResults, checks...)
	image, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
	}
	image.WithOptionalTag(version.Get().GitVersion)

	for nodeName, pods := range groupedPods {
		podName := fmt.Sprintf("diki-%s-%s", r.ID(), sharedv1r11.Generator.Generate(10))
		execPodTarget := rule.NewTarget("name", podName, "namespace", "kube-system", "kind", "pod")

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

		var (
			execContainerID     = execPod.Status.ContainerStatuses[0].ContainerID
			execBaseContainerID = strings.Split(execContainerID, "//")[1]
			execContainerPath   = fmt.Sprintf("/run/containerd/io.containerd.runtime.v2.task/k8s.io/%s/rootfs", execBaseContainerID)
		)

		slices.SortFunc(pods, func(a, b corev1.Pod) int {
			return cmp.Compare(a.Name, b.Name)
		})

		for _, pod := range pods {
			excludedSources := []string{"/lib/modules", "/usr/share/ca-certificates", "/var/log/journal"}
			mappedFileStats, err := intutils.GetMountedFilesStats(ctx, execContainerPath, podExecutor, pod, excludedSources)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			}

			var expectedFilePermissionsMax = "644"
			for containerName, fileStats := range mappedFileStats {
				for _, fileStat := range fileStats {
					if !strings.HasSuffix(fileStat.Path, ".crt") {
						continue
					}

					containerTarget := rule.NewTarget("name", pod.Name, "namespace", pod.Namespace, "kind", "pod", "containerName", containerName)
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
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
