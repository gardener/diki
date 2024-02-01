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
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	intutils "github.com/gardener/diki/pkg/internal/utils"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ rule.Rule = &Rule242445{}

type Rule242445 struct {
	InstanceID         string
	Client             client.Client
	Namespace          string
	PodContext         pod.PodContext
	ETCDMainSelector   labels.Selector
	ETCDEventsSelector labels.Selector
	Options            *option.FileOwnerOptions
	Logger             *slog.Logger
}

func (r *Rule242445) ID() string {
	return ID242445
}

func (r *Rule242445) Name() string {
	return "The Kubernetes component etcd must be owned by etcd (MEDIUM 242445)"
}

func (r *Rule242445) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}
	etcdMainSelector := labels.SelectorFromSet(labels.Set{"instance": "etcd-main"})
	etcdEventsSelector := labels.SelectorFromSet(labels.Set{"instance": "etcd-events"})

	if r.Options == nil {
		r.Options = &option.FileOwnerOptions{}
	}
	if len(r.Options.ExpectedFileOwner.Users) == 0 {
		r.Options.ExpectedFileOwner.Users = []string{"0"}
	}
	if len(r.Options.ExpectedFileOwner.Groups) == 0 {
		r.Options.ExpectedFileOwner.Groups = []string{"0"}
	}

	if r.ETCDMainSelector != nil {
		etcdMainSelector = r.ETCDMainSelector
	}

	if r.ETCDEventsSelector != nil {
		etcdEventsSelector = r.ETCDEventsSelector
	}

	target := rule.NewTarget()
	allPods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target.With("namespace", r.Namespace, "kind", "podList"))), nil
	}
	checkPodsSelectors := []labels.Selector{etcdMainSelector, etcdEventsSelector}
	checkPods := []corev1.Pod{}

	for _, podSelector := range checkPodsSelectors {
		pods := []corev1.Pod{}
		for _, p := range allPods {
			if podSelector.Matches(labels.Set(p.Labels)) && p.Namespace == r.Namespace {
				pods = append(pods, p)
			}
		}

		if len(pods) == 0 {
			checkResults = append(checkResults, rule.FailedCheckResult("Pods not found!", target.With("namespace", r.Namespace, "selector", podSelector.String())))
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
	groupedPods, checks := kubeutils.SelectPodOfReferenceGroup(checkPods, nodesAllocatablePods, target)
	checkResults = append(checkResults, checks...)
	image, err := imagevector.ImageVector().FindImage(ruleset.OpsToolbeltImageName)
	if err != nil {
		return rule.RuleResult{}, fmt.Errorf("failed to find image version for %s: %w", ruleset.OpsToolbeltImageName, err)
	}

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

		for _, pod := range pods {
			excludedSources := []string{"/lib/modules", "/usr/share/ca-certificates", "/var/log/journal"}
			mappedFileStats, err := intutils.GetMountedFilesStats(ctx, execContainerPath, podExecutor, pod, excludedSources)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			}

			for containerName, fileStats := range mappedFileStats {
				for _, fileStat := range fileStats {
					containerTarget := rule.NewTarget("name", pod.Name, "namespace", pod.Namespace, "kind", "pod", "containerName", containerName)
					checkResults = append(checkResults, intutils.MatchFileOwnersCases(fileStat, r.Options.ExpectedFileOwner.Users, r.Options.ExpectedFileOwner.Groups, containerTarget)...)
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