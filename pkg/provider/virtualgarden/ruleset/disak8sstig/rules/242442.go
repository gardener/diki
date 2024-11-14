// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"

	imageref "github.com/distribution/reference"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ rule.Rule = &Rule242442{}
var _ rule.Severity = &Rule242442{}

type Rule242442 struct {
	Client    client.Client
	Namespace string
}

func (r *Rule242442) ID() string {
	return sharedrules.ID242442
}

func (r *Rule242442) Name() string {
	return "Kubernetes must remove old components after updated versions have been installed."
}

func (r *Rule242442) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242442) Run(ctx context.Context) (rule.RuleResult, error) {
	images := map[string]string{}
	reportedImages := map[string]struct{}{}
	pods, err := kubeutils.GetPods(ctx, r.Client, r.Namespace, labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("namespace", r.Namespace, "kind", "podList"))), nil
	}

	checkResults := r.checkImages(pods, images, reportedImages)
	if len(checkResults) == 0 {
		return rule.Result(r, rule.PassedCheckResult("All found images use current versions.", rule.Target{})), nil
	}

	return rule.Result(r, checkResults...), nil
}

func (*Rule242442) checkImages(pods []corev1.Pod, images map[string]string, reportedImages map[string]struct{}) []rule.CheckResult {
	var checkResults []rule.CheckResult
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			containerStatusIdx := slices.IndexFunc(pod.Status.ContainerStatuses, func(containerStatus corev1.ContainerStatus) bool {
				return containerStatus.Name == container.Name
			})

			if containerStatusIdx < 0 {
				checkResults = append(checkResults, rule.ErroredCheckResult("containerStatus not found for container", rule.NewTarget("name", pod.Name, "container", container.Name, "kind", "pod")))
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
						target := rule.NewTarget("image", imageBase)
						checkResults = append(checkResults, rule.FailedCheckResult("Image is used with more than one versions.", target))
						reportedImages[imageBase] = struct{}{}
					}
				}
			} else {
				images[imageBase] = imageRef
			}
		}
	}
	return checkResults
}
