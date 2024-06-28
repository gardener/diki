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
)

var _ rule.Rule = &Rule242446{}

type Rule242446 struct {
	InstanceID      string
	Client          client.Client
	Namespace       string
	PodContext      pod.PodContext
	DeploymentNames []string
	Options         *option.FileOwnerOptions
	Logger          provider.Logger
}

func (r *Rule242446) ID() string {
	return ID242446
}

func (r *Rule242446) Name() string {
	return "The Kubernetes conf files must be owned by root (MEDIUM 242446)"
}

func (r *Rule242446) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}
	deploymentNames := []string{"kube-apiserver", "kube-controller-manager", "kube-scheduler"}
	options := option.FileOwnerOptions{}
	if r.Options != nil {
		options = *r.Options
	}
	if len(options.ExpectedFileOwner.Users) == 0 {
		options.ExpectedFileOwner.Users = []string{"0"}
	}
	if len(options.ExpectedFileOwner.Groups) == 0 {
		options.ExpectedFileOwner.Groups = []string{"0"}
	}

	if r.DeploymentNames != nil {
		deploymentNames = r.DeploymentNames
	}

	target := rule.NewTarget()
	allPods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target.With("namespace", r.Namespace, "kind", "podList"))), nil
	}
	checkPods := []corev1.Pod{}

	for _, deploymentName := range deploymentNames {
		pods, err := kubeutils.GetDeploymentPods(ctx, r.Client, deploymentName, r.Namespace)
		if err != nil {
			checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), target.With("kind", "podList")))
			continue
		}

		if len(pods) == 0 {
			checkResults = append(checkResults, rule.ErroredCheckResult("pods not found for deployment", target.With("name", deploymentName, "kind", "Deployment", "namespace", r.Namespace)))
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

		// The rule is not explained in details and it is ambiguous
		// It refers to kubeconfigs (and other configuration files?)
		// This is why we check all files and not only specific ones
		for _, pod := range pods {
			excludedSources := []string{"/lib/modules", "/usr/share/ca-certificates", "/var/log/journal"}
			mappedFileStats, err := intutils.GetMountedFilesStats(ctx, execContainerPath, podExecutor, pod, excludedSources)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), execPodTarget))
			}

			for containerName, fileStats := range mappedFileStats {
				for _, fileStat := range fileStats {
					containerTarget := rule.NewTarget("name", pod.Name, "namespace", pod.Namespace, "kind", "pod", "containerName", containerName)
					checkResults = append(checkResults, intutils.MatchFileOwnersCases(fileStat, options.ExpectedFileOwner.Users, options.ExpectedFileOwner.Groups, containerTarget)...)
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
