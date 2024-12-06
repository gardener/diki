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
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var (
	_ rule.Rule     = &Rule242466{}
	_ rule.Severity = &Rule242466{}
)

type Rule242466 struct {
	InstanceID string
	Client     client.Client
	Namespace  string
	PodContext pod.PodContext
	Logger     provider.Logger
}

func (r *Rule242466) ID() string {
	return sharedrules.ID242466
}

func (r *Rule242466) Name() string {
	return "The Kubernetes PKI CRT must have file permissions set to 644 or more restrictive."
}

func (r *Rule242466) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242466) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults               []rule.CheckResult
		expectedFilePermissionsMax = "644"
		// TODO: Drop support for "instance" etcd label in a future release
		// "instance" label is no longer in use for etcd-druid versions >= v0.23. ref: https://github.com/gardener/etcd-druid/pull/777
		etcdMainOldSelector = labels.SelectorFromSet(labels.Set{"instance": "virtual-garden-etcd-main"})
		etcdMainSelector    = labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": "virtual-garden-etcd-main"})
		// TODO: Drop support for "instance" etcd label in a future release
		// "instance" label is no longer in use for etcd-druid versions >= v0.23. ref: https://github.com/gardener/etcd-druid/pull/777
		etcdEventsOldSelector = labels.SelectorFromSet(labels.Set{"instance": "virtual-garden-etcd-events"})
		etcdEventsSelector    = labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": "virtual-garden-etcd-events"})
		deploymentNames       = []string{"virtual-garden-kube-apiserver", "virtual-garden-kube-controller-manager"}
	)

	allPods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList"))), nil
	}

	var (
		checkPods               []corev1.Pod
		podOldSelectors         = []labels.Selector{etcdMainOldSelector, etcdEventsOldSelector}
		podSelectors            = []labels.Selector{etcdMainSelector, etcdEventsSelector}
		oldSelectorCheckResults []rule.CheckResult
	)

	for _, podSelector := range podOldSelectors {
		var pods []corev1.Pod
		for _, p := range allPods {
			if podSelector.Matches(labels.Set(p.Labels)) && p.Namespace == r.Namespace {
				pods = append(pods, p)
			}
		}

		if len(pods) == 0 {
			oldSelectorCheckResults = append(oldSelectorCheckResults, rule.ErroredCheckResult("pods not found", rule.NewTarget("namespace", r.Namespace, "selector", podSelector.String())))
			continue
		}

		checkPods = append(checkPods, pods...)
	}

	if len(checkPods) == 0 {
		for _, podSelector := range podSelectors {
			var pods []corev1.Pod
			for _, p := range allPods {
				if podSelector.Matches(labels.Set(p.Labels)) && p.Namespace == r.Namespace {
					pods = append(pods, p)
				}
			}

			if len(pods) == 0 {
				checkResults = append(checkResults, rule.ErroredCheckResult("pods not found", rule.NewTarget("namespace", r.Namespace, "selector", podSelector.String())))
				continue
			}

			checkPods = append(checkPods, pods...)
		}
	} else {
		checkResults = append(checkResults, oldSelectorCheckResults...)
	}

	for _, deploymentName := range deploymentNames {
		pods, err := kubeutils.GetDeploymentPods(ctx, r.Client, deploymentName, r.Namespace)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList")))
			continue
		}

		if len(pods) == 0 {
			checkResults = append(checkResults, rule.ErroredCheckResult("pods not found for deployment", rule.NewTarget("name", deploymentName, "kind", "Deployment", "namespace", r.Namespace)))
			continue
		}

		checkPods = append(checkPods, pods...)
	}

	if len(checkPods) == 0 {
		return rule.Result(r, checkResults...), nil
	}

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "nodeList"))), nil
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
		checkResults = append(checkResults,
			r.checkPods(ctx, pods, nodeName, image.String(), expectedFilePermissionsMax)...)
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule242466) checkPods(
	ctx context.Context,
	pods []corev1.Pod,
	nodeName, imageName string,
	expectedFilePermissionsMax string,
) []rule.CheckResult {
	var (
		checkResults     []rule.CheckResult
		podName          = fmt.Sprintf("diki-%s-%s", r.ID(), sharedrules.Generator.Generate(10))
		execPodTarget    = rule.NewTarget("name", podName, "namespace", "kube-system", "kind", "pod")
		additionalLabels = map[string]string{pod.LabelInstanceID: r.InstanceID}
	)

	defer func() {
		timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()

		if err := r.PodContext.Delete(timeoutCtx, podName, "kube-system"); err != nil {
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
			for _, fileStat := range fileStats {
				if !strings.HasSuffix(fileStat.Path, ".crt") && !strings.HasSuffix(fileStat.Path, ".pem") {
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
	return checkResults
}
