// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10

import (
	"context"
	"log/slog"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242442{}

type Rule242442 struct {
	ClusterClient         client.Client
	ControlPlaneClient    client.Client
	ControlPlaneNamespace string
	Logger                *slog.Logger
}

func (r *Rule242442) ID() string {
	return ID242442
}

func (r *Rule242442) Name() string {
	return "Kubernetes must remove old components after updated versions have been installed (MEDIUM 242442)"
}

func (r *Rule242442) Run(ctx context.Context) (rule.RuleResult, error) {
	images := map[string]string{}
	reportedImages := map[string]struct{}{}
	seedPods, err := kubeutils.GetPods(ctx, r.ControlPlaneClient, r.ControlPlaneNamespace, labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), gardener.NewTarget("cluster", "seed", "namespace", r.ControlPlaneNamespace, "kind", "podList"))), nil
	}

	checkResults := r.checkImages(seedPods, images, reportedImages)

	shootPods, err := kubeutils.GetPods(ctx, r.ClusterClient, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), gardener.NewTarget("cluster", "shoot", "kind", "podList"))), nil
	}

	checkResults = append(checkResults, r.checkImages(shootPods, images, reportedImages)...)

	if len(checkResults) == 0 {
		return rule.SingleCheckResult(r, rule.PassedCheckResult("All found images use current versions.", &gardener.Target{})), nil
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (*Rule242442) checkImages(pods []corev1.Pod, images map[string]string, reportedImages map[string]struct{}) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			imageRef := container.Image
			imageBase := strings.Split(strings.Split(imageRef, ":")[0], "@")[0]
			if _, ok := images[imageBase]; ok {
				if images[imageBase] != imageRef {
					if _, reported := reportedImages[imageBase]; !reported {
						target := gardener.NewTarget("image", imageBase)
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
