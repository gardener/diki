// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	disaoptions "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var (
	_ rule.Rule          = &Rule2005{}
	_ rule.Severity      = &Rule2005{}
	_ disaoptions.Option = &Options2005{}
)

type Rule2005 struct {
	Client  client.Client
	Options *Options2005
}

type Options2005 struct {
	AllowedImages []AllowedImage `json:"allowedImages" yaml:"allowedImages"`
}

type AllowedImage struct {
	Prefix string `json:"prefix" yaml:"prefix"`
}

// Validate validates that option configurations are correctly defined
func (o Options2005) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs      field.ErrorList
		allowImgPath = fldPath.Child("allowedImages")
	)

	if len(o.AllowedImages) == 0 {
		return field.ErrorList{field.Required(allowImgPath, "must not be empty")}
	}

	for i, r := range o.AllowedImages {
		if len(r.Prefix) == 0 {
			allErrs = append(allErrs, field.Required(allowImgPath.Index(i).Child("prefix"), "must not be empty"))
		}
	}

	return allErrs
}

func (r *Rule2005) ID() string {
	return "2005"
}

func (r *Rule2005) Name() string {
	return "Container images must come from trusted repositories."
}

func (r *Rule2005) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule2005) Run(ctx context.Context) (rule.RuleResult, error) {
	if r.Options == nil {
		return rule.Result(r, rule.FailedCheckResult("There are no allowed images in rule options.", nil)), nil
	}

	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "PodList"))), nil
	}

	if len(pods) == 0 {
		return rule.Result(r, rule.PassedCheckResult("The cluster does not have any Pods.", rule.NewTarget())), nil
	}

	filteredPods := kubeutils.FilterPodsByOwnerRef(pods)

	replicaSets, err := kubeutils.GetReplicaSets(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "ReplicaSetList"))), nil
	}

	var checkResults []rule.CheckResult

	for _, pod := range filteredPods {
		podTarget := kubeutils.TargetWithPod(rule.NewTarget(), pod, replicaSets)

		for _, container := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			var (
				containerTarget   = podTarget.With("container", container.Name)
				containerStatuses = slices.Concat(pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses)
			)

			containerStatusIdx := slices.IndexFunc(containerStatuses, func(containerStatus corev1.ContainerStatus) bool {
				return containerStatus.Name == container.Name
			})

			if containerStatusIdx < 0 {
				checkResults = append(checkResults, rule.ErroredCheckResult("containerStatus not found for container", containerTarget))
				continue
			}

			if len(containerStatuses[containerStatusIdx].ImageID) == 0 {
				checkResults = append(checkResults, rule.WarningCheckResult("ImageID is empty in container status.", containerTarget))
				continue
			}

			imageRefTarget := containerTarget.With("imageRef", containerStatuses[containerStatusIdx].ImageID)

			if slices.ContainsFunc(r.Options.AllowedImages, func(allowedImage AllowedImage) bool {
				return strings.HasPrefix(containerStatuses[containerStatusIdx].ImageID, allowedImage.Prefix)
			}) {
				checkResults = append(checkResults, rule.PassedCheckResult("Image has allowed prefix.", imageRefTarget))
			} else {
				checkResults = append(checkResults, rule.FailedCheckResult("Image has not allowed prefix.", imageRefTarget))
			}
		}
	}

	return rule.Result(r, checkResults...), nil
}
