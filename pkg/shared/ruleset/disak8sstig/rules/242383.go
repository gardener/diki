// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"

	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ rule.Rule = &Rule242383{}

type Rule242383 struct {
	Client  client.Client
	Options *Options242383
}

type Options242383 struct {
	AcceptedResources []AcceptedResources242383 `json:"acceptedResources" yaml:"acceptedResources"`
}

var _ option.Option = (*Options242383)(nil)

type AcceptedResources242383 struct {
	ObjectSelector
	Justification string `json:"justification" yaml:"justification"`
	Status        string `json:"status" yaml:"status"`
}

func (o Options242383) Validate() field.ErrorList {
	var (
		allErrs  field.ErrorList
		rootPath = field.NewPath("acceptedResources")
	)
	for _, p := range o.AcceptedResources {
		allErrs = append(allErrs, p.Validate()...)
		if !slices.Contains([]string{"Passed", "Accepted"}, p.Status) && len(p.Status) > 0 {
			allErrs = append(allErrs, field.Invalid(rootPath.Child("status"), p.Status, "must be one of 'Passed' or 'Accepted'"))
		}
	}
	return allErrs
}

type ObjectSelector struct {
	APIVersion           string            `json:"apiVersion" yaml:"apiVersion"`
	Kind                 string            `json:"kind" yaml:"kind"`
	MatchLabels          map[string]string `json:"matchLabels" yaml:"matchLabels"`
	NamespaceMatchLabels map[string]string `json:"namespaceMatchLabels" yaml:"namespaceMatchLabels"`
}

var _ option.Option = (*ObjectSelector)(nil)

func (s ObjectSelector) Validate() field.ErrorList {
	var (
		allErrs          field.ErrorList
		rootPath         = field.NewPath("acceptedResources")
		checkedResources = map[string][]string{
			"v1":             {"Pod", "ReplicationController", "Service"},
			"apps/v1":        {"Deployment", "DaemonSet", "ReplicaSet", "StatefulSet"},
			"batch/v1":       {"Job", "CronJob"},
			"autoscaling/v1": {"HorizontalPodAutoscaler"},
		}
	)

	if len(s.NamespaceMatchLabels) == 0 {
		allErrs = append(allErrs, field.Required(rootPath.Child("namespaceMatchLabels"), "must not be empty"))
	}

	if len(s.MatchLabels) == 0 {
		allErrs = append(allErrs, field.Required(rootPath.Child("matchLabels"), "must not be empty"))
	}

	if kinds, ok := checkedResources[s.APIVersion]; !ok {
		allErrs = append(allErrs, field.Invalid(rootPath.Child("apiVersion"), s.APIVersion, "not checked apiVersion"))
	} else if !slices.Contains(kinds, s.Kind) && s.Kind != "*" {
		allErrs = append(allErrs, field.Invalid(rootPath.Child("kind"), s.Kind, fmt.Sprintf("not checked kind for apiVerion %s", s.APIVersion)))
	}

	allErrs = append(allErrs, metav1validation.ValidateLabels(s.MatchLabels, rootPath.Child("matchLabels"))...)
	allErrs = append(allErrs, metav1validation.ValidateLabels(s.NamespaceMatchLabels, rootPath.Child("namespaceMatchLabels"))...)

	return allErrs
}

func (r *Rule242383) ID() string {
	return ID242383
}

func (r *Rule242383) Name() string {
	return "Kubernetes must separate user functionality (MEDIUM 242383)"
}

func (r *Rule242383) Run(ctx context.Context) (rule.RuleResult, error) {
	allNamespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
	}
	checkResults := []rule.CheckResult{}
	systemNamespaces := []string{"default", "kube-public", "kube-node-lease"}
	acceptedResources := []AcceptedResources242383{
		{
			// The 'kubernetes' Service is a required system resource exposing the kubernetes API server
			ObjectSelector: ObjectSelector{
				APIVersion: "v1",
				Kind:       "Service",
				MatchLabels: map[string]string{
					"component": "apiserver",
					"provider":  "kubernetes",
				},
				NamespaceMatchLabels: map[string]string{
					"kubernetes.io/metadata.name": "default",
				},
			},
			Status: "Passed",
		},
	}

	if r.Options != nil && r.Options.AcceptedResources != nil {
		acceptedResources = append(acceptedResources, r.Options.AcceptedResources...)
	}

	notDikiPodReq, err := labels.NewRequirement(pod.LabelComplianceRoleKey, selection.NotEquals, []string{pod.LabelComplianceRolePrivPod})
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
	}

	selector := labels.NewSelector().Add(*notDikiPodReq)

	for _, namespace := range systemNamespaces {
		partialMetadata, err := kubeutils.GetAllObjectsMetadata(ctx, r.Client, namespace, selector, 300)
		if err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("namespace", namespace, "kind", "allList"))), nil
		}
		for _, p := range partialMetadata {
			target := rule.NewTarget("name", p.Name, "namespace", p.Namespace, "kind", p.Kind)
			acceptedIdx := slices.IndexFunc(acceptedResources, func(acceptedResource AcceptedResources242383) bool {
				return (p.APIVersion == acceptedResource.ObjectSelector.APIVersion) &&
					(acceptedResource.ObjectSelector.Kind == "*" || p.Kind == acceptedResource.ObjectSelector.Kind) &&
					utils.MatchLabels(allNamespaces[namespace].Labels, acceptedResource.NamespaceMatchLabels) &&
					utils.MatchLabels(p.Labels, acceptedResource.ObjectSelector.MatchLabels)
			})

			if acceptedIdx < 0 {
				checkResults = append(checkResults, rule.FailedCheckResult("Found user resource in system namespaces.", target))
				continue
			}

			acceptedResource := acceptedResources[acceptedIdx]

			msg := strings.TrimSpace(acceptedResource.Justification)
			status := strings.TrimSpace(acceptedResource.Status)
			switch status {
			case "Passed":
				if len(msg) == 0 {
					msg = "System resource in system namespaces."
				}
				checkResults = append(checkResults, rule.PassedCheckResult(msg, target))
			case "Accepted", "":
				if len(msg) == 0 {
					msg = "Accepted user resource in system namespaces."
				}
				checkResults = append(checkResults, rule.AcceptedCheckResult(msg, target))
			default:
				checkResults = append(checkResults, rule.WarningCheckResult(fmt.Sprintf("unrecognized status: %s", status), target))
			}
		}
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
