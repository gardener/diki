// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"
	"strings"

	imageref "github.com/distribution/reference"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule2005{}
	_ rule.Severity = &Rule2005{}
)

type Rule2005 struct {
	Client  client.Client
	Options *Options2005
}

type Options2005 struct {
	AllowedRepositories []AllowedRepository `json:"allowedRepositories" yaml:"allowedRepositories"`
}

type AllowedRepository struct {
	Prefix string `json:"prefix" yaml:"prefix"`
}

// Validate validates that option configurations are correctly defined
func (o Options2005) Validate() field.ErrorList {
	var (
		allErrs       field.ErrorList
		allowRepoPath = field.NewPath("allowedRepositories")
	)

	if len(o.AllowedRepositories) == 0 {
		return field.ErrorList{field.Required(allowRepoPath, "must not be empty")}
	}

	for i, r := range o.AllowedRepositories {
		if len(r.Prefix) == 0 {
			allErrs = append(allErrs, field.Required(allowRepoPath.Index(i).Child("prefix"), "must not be empty"))
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
		return rule.Result(r, rule.ErroredCheckResult("rule options are missing, but required", nil)), nil
	}

	var checkResults []rule.CheckResult

	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList"))), nil
	}

	for _, pod := range pods {
		podTarget := rule.NewTarget("kind", "pod", "name", pod.Name, "namespace", pod.Namespace)
		for _, container := range pod.Spec.Containers {
			containerTarget := podTarget.With("container", container.Name)

			containerStatusIdx := slices.IndexFunc(pod.Status.ContainerStatuses, func(containerStatus corev1.ContainerStatus) bool {
				return containerStatus.Name == container.Name
			})

			if containerStatusIdx < 0 {
				checkResults = append(checkResults, rule.ErroredCheckResult("containerStatus not found for container", containerTarget))
				continue
			}

			imageRef := pod.Status.ContainerStatuses[containerStatusIdx].ImageID
			named, err := imageref.ParseNormalizedNamed(imageRef)
			if err != nil {
				checkResults = append(checkResults, rule.ErroredCheckResult(err.Error(), containerTarget.With("imageRef", imageRef)))
				continue
			}
			imageBase := named.Name()

			if slices.ContainsFunc(r.Options.AllowedRepositories, func(allowedRepository AllowedRepository) bool {
				return strings.HasPrefix(imageBase, allowedRepository.Prefix)
			}) {
				checkResults = append(checkResults, rule.PassedCheckResult("Image comes from allowed repository.", containerTarget.With("imageBase", imageBase)))
			} else {
				checkResults = append(checkResults, rule.FailedCheckResult("Image comes from not allowed repository.", containerTarget.With("imageBase", imageBase)))
			}
		}
	}

	return rule.Result(r, checkResults...), nil
}
