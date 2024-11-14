// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"

	imageref "github.com/distribution/reference"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ rule.Rule = &Rule242442{}
var _ rule.Severity = &Rule242442{}

type Rule242442 struct {
	Client  client.Client
	Options *Options242442
}

type Options242442 struct {
	KubeProxyMatchLabels map[string]string `json:"kubeProxyMatchLabels" yaml:"kubeProxyMatchLabels"`
}

var _ option.Option = (*Options242442)(nil)

func (o Options242442) Validate() field.ErrorList {
	return validation.ValidateLabels(o.KubeProxyMatchLabels, field.NewPath("kubeProxyMatchLabels"))
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
	var (
		checkResults      []rule.CheckResult
		nodeKubeProxyPods = map[string][]corev1.Pod{}
		kubeProxySelector = labels.SelectorFromSet(labels.Set{"role": "proxy"})
	)

	if r.Options != nil && len(r.Options.KubeProxyMatchLabels) > 0 {
		kubeProxySelector = labels.SelectorFromSet(labels.Set(r.Options.KubeProxyMatchLabels))
	}

	kubeProxyPods, err := kubeutils.GetPods(ctx, r.Client, "", kubeProxySelector, 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList"))), nil
	}

	if len(kubeProxyPods) == 0 {
		return rule.Result(r, rule.ErroredCheckResult("kube-proxy pods not found", rule.NewTarget("selector", kubeProxySelector.String()))), nil
	}

	for _, pod := range kubeProxyPods {
		nodeKubeProxyPods[pod.Spec.NodeName] = append(nodeKubeProxyPods[pod.Spec.NodeName], pod)
	}

	for node, pods := range nodeKubeProxyPods {
		target := rule.NewTarget("kind", "node", "name", node)
		checkResults = append(checkResults, r.checkImages(pods, target)...)
	}

	if len(checkResults) == 0 {
		return rule.Result(r, rule.PassedCheckResult("All found images use current versions.", rule.Target{})), nil
	}

	return rule.Result(r, checkResults...), nil
}

func (*Rule242442) checkImages(pods []corev1.Pod, target rule.Target) []rule.CheckResult {
	var (
		images         = map[string]string{}
		reportedImages = map[string]struct{}{}
		checkResults   []rule.CheckResult
	)
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			containerStatusIdx := slices.IndexFunc(pod.Status.ContainerStatuses, func(containerStatus corev1.ContainerStatus) bool {
				return containerStatus.Name == container.Name
			})

			if containerStatusIdx < 0 {
				checkResults = append(checkResults, rule.ErroredCheckResult("containerStatus not found for container", rule.NewTarget("name", pod.Name, "namespace", pod.Namespace, "container", container.Name, "kind", "pod")))
				continue
			}

			imageRef := pod.Status.ContainerStatuses[containerStatusIdx].ImageID
			named, err := imageref.ParseNormalizedNamed(imageRef)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), target.With("imageRef", imageRef)))
				continue
			}
			imageBase := named.Name()

			if _, ok := images[imageBase]; ok && images[imageBase] != imageRef {
				if _, reported := reportedImages[imageBase]; !reported {
					checkResults = append(checkResults, rule.FailedCheckResult("Image is used with more than one versions.", target.With("image", imageBase)))
					reportedImages[imageBase] = struct{}{}
				}
			} else {
				images[imageBase] = imageRef
			}
		}
	}
	return checkResults
}
