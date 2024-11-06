// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"

	imageref "github.com/distribution/reference"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ rule.Rule = &Rule242442{}

type Rule242442 struct {
	ClusterClient         client.Client
	ControlPlaneClient    client.Client
	ControlPlaneNamespace string
}

func (r *Rule242442) ID() string {
	return sharedrules.ID242442
}

func (r *Rule242442) Name() string {
	return "Kubernetes must remove old components after updated versions have been installed (MEDIUM 242442)"
}

func (r *Rule242442) Run(ctx context.Context) (rule.RuleResult, error) {
	seedPods, err := kubeutils.GetPods(ctx, r.ControlPlaneClient, r.ControlPlaneNamespace, labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("cluster", "seed", "namespace", r.ControlPlaneNamespace, "kind", "podList"))), nil
	}

	checkResults := r.checkImages("seed", seedPods)

	managedByGardenerReq, err := labels.NewRequirement(resourcesv1alpha1.ManagedBy, selection.Equals, []string{"gardener"})
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
	}

	managedByGardenerSelector := labels.NewSelector().Add(*managedByGardenerReq)
	shootPods, err := kubeutils.GetPods(ctx, r.ClusterClient, "", managedByGardenerSelector, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("cluster", "shoot", "kind", "podList"))), nil
	}

	checkResults = append(checkResults, r.checkImages("shoot", shootPods)...)

	if len(checkResults) == 0 {
		return rule.Result(r, rule.PassedCheckResult("All found images use current versions.", rule.Target{})), nil
	}

	return rule.Result(r, checkResults...), nil
}

func (*Rule242442) checkImages(cluster string, pods []corev1.Pod) []rule.CheckResult {
	var (
		checkResults    []rule.CheckResult
		podsByNamespace = map[string][]corev1.Pod{}
	)

	for _, pod := range pods {
		podsByNamespace[pod.Namespace] = append(podsByNamespace[pod.Namespace], pod)
	}

	for namespace, groupedPods := range podsByNamespace {
		var (
			reportedImages = map[string]struct{}{}
			images         = map[string]string{}
		)

		for _, pod := range groupedPods {
			for _, container := range pod.Spec.Containers {
				containerStatusIdx := slices.IndexFunc(pod.Status.ContainerStatuses, func(containerStatus corev1.ContainerStatus) bool {
					return containerStatus.Name == container.Name
				})

				if containerStatusIdx < 0 {
					checkResults = append(checkResults, rule.ErroredCheckResult("containerStatus not found for container", rule.NewTarget("cluster", cluster, "name", pod.Name, "container", container.Name, "kind", "pod")))
					continue
				}

				imageRef := pod.Status.ContainerStatuses[containerStatusIdx].ImageID
				named, err := imageref.ParseNormalizedNamed(imageRef)
				if err != nil {
					checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), rule.NewTarget("imageRef", imageRef)))
					continue
				}
				imageBase := named.Name()

				if _, ok := images[imageBase]; ok {
					if images[imageBase] != imageRef {
						if _, reported := reportedImages[imageBase]; !reported {
							target := rule.NewTarget("cluster", cluster, "image", imageBase, "namespace", namespace)
							checkResults = append(checkResults, rule.FailedCheckResult("Image is used with more than one versions.", target))
							reportedImages[imageBase] = struct{}{}
						}
					}
				} else {
					images[imageBase] = imageRef
				}
			}
		}
	}
	return checkResults
}
