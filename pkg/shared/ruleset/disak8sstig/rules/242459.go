// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
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
)

var (
	_ rule.Rule     = &Rule242459{}
	_ rule.Severity = &Rule242459{}
)

type Rule242459 struct {
	InstanceID string
	Client     client.Client
	Namespace  string
	PodContext pod.PodContext
	Logger     provider.Logger
	// TODO: Drop support for "instance" etcd label in a future release
	// "instance" label is no longer in use for etcd-druid versions >= v0.23. ref: https://github.com/gardener/etcd-druid/pull/777
	ETCDMainOldSelector labels.Selector
	ETCDMainSelector    labels.Selector
	// TODO: Drop support for "instance" etcd label in a future release
	// "instance" label is no longer in use for etcd-druid versions >= v0.23. ref: https://github.com/gardener/etcd-druid/pull/777
	ETCDEventsOldSelector labels.Selector
	ETCDEventsSelector    labels.Selector
}

func (r *Rule242459) ID() string {
	return ID242459
}

func (r *Rule242459) Name() string {
	return "The Kubernetes etcd must have file permissions set to 644 or more restrictive."
}

func (r *Rule242459) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242459) Run(ctx context.Context) (rule.RuleResult, error) {
	var (
		checkResults []rule.CheckResult
		// TODO: Drop support for "instance" etcd label in a future release
		// "instance" label is no longer in use for etcd-druid versions >= v0.23. ref: https://github.com/gardener/etcd-druid/pull/777
		etcdMainOldSelector = labels.SelectorFromSet(labels.Set{"instance": "etcd-main"})
		etcdMainSelector    = labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": "etcd-main"})
		// TODO: Drop support for "instance" etcd label in a future release
		// "instance" label is no longer in use for etcd-druid versions >= v0.23. ref: https://github.com/gardener/etcd-druid/pull/777
		etcdEventsOldSelector = labels.SelectorFromSet(labels.Set{"instance": "etcd-events"})
		etcdEventsSelector    = labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": "etcd-events"})
	)

	if r.ETCDMainOldSelector != nil {
		etcdMainOldSelector = r.ETCDMainOldSelector
	}

	if r.ETCDMainSelector != nil {
		etcdMainSelector = r.ETCDMainSelector
	}

	if r.ETCDEventsOldSelector != nil {
		etcdEventsOldSelector = r.ETCDEventsOldSelector
	}

	if r.ETCDEventsSelector != nil {
		etcdEventsSelector = r.ETCDEventsSelector
	}

	var (
		checkPods               []corev1.Pod
		oldSelectorCheckResults []rule.CheckResult
		checkOldPodSelectors    = []labels.Selector{etcdMainOldSelector, etcdEventsOldSelector}
		checkPodSelectors       = []labels.Selector{etcdMainSelector, etcdEventsSelector}
	)

	target := rule.NewTarget()
	allPods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target.With("kind", "PodList"))), nil
	}

	for _, podSelector := range checkOldPodSelectors {
		var pods []corev1.Pod
		for _, p := range allPods {
			if podSelector.Matches(labels.Set(p.Labels)) && p.Namespace == r.Namespace {
				pods = append(pods, p)
			}
		}

		if len(pods) == 0 {
			oldSelectorCheckResults = append(oldSelectorCheckResults, rule.ErroredCheckResult("pods not found", target.With("namespace", r.Namespace, "selector", podSelector.String())))
			continue
		}

		checkPods = append(checkPods, pods...)
	}

	if len(checkPods) == 0 {
		for _, podSelector := range checkPodSelectors {
			var pods []corev1.Pod
			for _, p := range allPods {
				if podSelector.Matches(labels.Set(p.Labels)) && p.Namespace == r.Namespace {
					pods = append(pods, p)
				}
			}

			if len(pods) == 0 {
				checkResults = append(checkResults, rule.ErroredCheckResult("pods not found", target.With("namespace", r.Namespace, "selector", podSelector.String())))
				continue
			}

			checkPods = append(checkPods, pods...)
		}
	} else {
		checkResults = append(checkResults, oldSelectorCheckResults...)
	}

	if len(checkPods) == 0 {
		return rule.Result(r, checkResults...), nil
	}

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target.With("kind", "NodeList"))), nil
	}

	replicaSets, err := kubeutils.GetReplicaSets(ctx, r.Client, r.Namespace, labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("namespace", r.Namespace, "kind", "ReplicaSetList"))), nil
	}

	nodesAllocatablePods := kubeutils.GetNodesAllocatablePodsNum(allPods, nodes)
	groupedPods, checks := kubeutils.SelectPodOfReferenceGroup(checkPods, replicaSets, nodesAllocatablePods, target)
	checkResults = append(checkResults, checks...)
	image, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
	}
	image.WithOptionalTag(version.Get().GitVersion)

	for nodeName, pods := range groupedPods {
		var (
			podName       = fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
			execPodTarget = target.With("name", podName, "namespace", "kube-system", "kind", "Pod")
		)

		defer func() {
			timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second*30)
			defer cancel()

			if err := r.PodContext.Delete(timeoutCtx, podName, "kube-system"); err != nil {
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

		for _, pod := range pods {
			excludedSources := []string{"/lib/modules", "/usr/share/ca-certificates", "/var/log/journal"}
			mappedFileStats, err := intutils.GetMountedFilesStats(ctx, execContainerPath, podExecutor, pod, excludedSources)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			}

			for containerName, fileStats := range mappedFileStats {
				for _, fileStat := range fileStats {
					expectedFilePermissionsMax := "644"
					if strings.Contains(fileStat.Destination, "/etcd/data") {
						expectedFilePermissionsMax = "600"
					}

					containerTarget := kubeutils.TargetWithPod(rule.NewTarget("containerName", containerName), pod, replicaSets)
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

	return rule.Result(r, checkResults...), nil
}
