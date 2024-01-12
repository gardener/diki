// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	dikiutils "github.com/gardener/diki/pkg/internal/utils"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242459{}

type Rule242459 struct {
	InstanceID         string
	Client             client.Client
	Namespace          string
	PodContext         pod.PodContext
	ETCDMainInstance   string
	ETCDEventsInstance string
	Logger             *slog.Logger
}

func (r *Rule242459) ID() string {
	return ID242459
}

func (r *Rule242459) Name() string {
	return "The Kubernetes etcd must have file permissions set to 644 or more restrictive (MEDIUM 242459)"
}

func (r *Rule242459) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}
	etcdMainInstance := "etcd-main"
	etcdEventsInstance := "etcd-events"

	if r.ETCDMainInstance != "" {
		etcdMainInstance = r.ETCDMainInstance
	}

	if r.ETCDEventsInstance != "" {
		etcdEventsInstance = r.ETCDEventsInstance
	}

	target := rule.NewTarget()
	allPods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target.With("namespace", r.Namespace, "kind", "podList"))), nil
	}
	checkPodsInstances := []string{etcdMainInstance, etcdEventsInstance}
	checkPods := []corev1.Pod{}

	for _, checkPodInstance := range checkPodsInstances {
		instanceReq, err := labels.NewRequirement("instance", selection.Equals, []string{checkPodInstance})
		if err != nil {
			return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
		}

		podSelector := labels.NewSelector().Add(*instanceReq)
		pods := []corev1.Pod{}

		for _, p := range allPods {
			if podSelector.Matches(labels.Set(p.Labels)) && p.Namespace == r.Namespace {
				pods = append(pods, p)
			}
		}

		if len(pods) == 0 {
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("%s pods not found!", checkPodInstance), target))
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
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target.With("kind", "nodeList"))), nil
	}
	nodesAllocatablePods := kubeutils.GetNodesAllocatablePodsNum(allPods, nodes)
	groupedPods, checkResults := kubeutils.SelectPodOfReferenceGroup(checkPods, nodesAllocatablePods, target)
	image, err := imagevector.ImageVector().FindImage(ruleset.OpsToolbeltImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", ruleset.OpsToolbeltImageName, err)
	}

	for nodeName, pods := range groupedPods {
		podName := fmt.Sprintf("diki-%s-%s", r.ID(), Generator.Generate(10))
		execPodTarget := target.With("name", podName, "namespace", "kube-system", "kind", "pod")

		var podExecutor pod.PodExecutor
		var err error
		additionalLabels := map[string]string{
			pod.LabelInstanceID: r.InstanceID,
		}

		defer func() {
			if err := r.PodContext.Delete(ctx, podName, "kube-system"); err != nil {
				r.Logger.Error(err.Error())
			}
		}()

		podExecutor, err = r.PodContext.Create(ctx, pod.NewPrivilegedPod(podName, "kube-system", image.String(), nodeName, additionalLabels))
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
			target = target.With("name", pod.Name, "namespace", pod.Namespace, "kind", "pod")
			excludedSources := []string{"/lib/modules", "/usr/share/ca-certificates", "/var/log/journal"}
			mappedFileStats, err := dikiutils.GetMountedFilesStats(ctx, execContainerPath, podExecutor, pod, excludedSources)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			}
			expectedFilePermissionsMax := "600"

			for containerName, fileStats := range mappedFileStats {
				for _, fileStat := range fileStats {
					target = target.With("name", pod.Name, "containerName", containerName, "namespace", pod.Namespace, "kind", "pod")
					exceedFilePermissions, err := dikiutils.ExceedFilePermissions(fileStat.Permissions, expectedFilePermissionsMax)
					if err != nil {
						checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), target))
						continue
					}

					if exceedFilePermissions {
						detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, permissions: %s, expectedPermissionsMax: %s", fileStat.Path, fileStat.Permissions, expectedFilePermissionsMax))
						checkResults = append(checkResults, rule.FailedCheckResult("File has too wide permissions", detailedTarget))
						continue
					}

					detailedTarget := target.With("details", fmt.Sprintf("fileName: %s, permissions: %s", fileStat.Path, fileStat.Permissions))
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
