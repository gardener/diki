// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

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
)

var _ rule.Rule = &Rule242383{}

type Rule242383 struct {
	Client  client.Client
	Options *Options242383
}

type Options242383 struct {
	AcceptedResources []AcceptedResources242383 `json:"acceptedResources" yaml:"acceptedResources"`
}

type AcceptedResources242383 struct {
	SelectResource
	Justification string `json:"justification" yaml:"justification"`
	Status        string `json:"status" yaml:"status"`
}

type SelectResource struct {
	APIVersion     string            `json:"apiVersion" yaml:"apiVersion"`
	Kind           string            `json:"kind" yaml:"kind"`
	MatchLabels    map[string]string `json:"matchLabels" yaml:"matchLabels"`
	NamespaceNames []string          `json:"namespaceNames" yaml:"namespaceNames"`
}

func (o Options242383) Validate() field.ErrorList {
	var (
		allErrs          field.ErrorList
		pathRoot         = field.NewPath("acceptedResources")
		checkedResources = map[string][]string{
			"v1":             {"Pod", "ReplicationController", "Service"},
			"apps/v1":        {"Deployment", "DaemonSet", "ReplicaSet", "StatefulSet"},
			"batch/v1":       {"Job", "CronJob"},
			"autoscaling/v1": {"HorizontalPodAutoscaler"},
		}
	)
	for _, p := range o.AcceptedResources {
		if kinds, ok := checkedResources[p.APIVersion]; !ok {
			allErrs = append(allErrs, field.Invalid(pathRoot.Child("apiVersion"), p.APIVersion, "not checked apiVersion"))
		} else if !slices.Contains(kinds, p.Kind) && p.Kind != "*" {
			allErrs = append(allErrs, field.Invalid(pathRoot.Child("kind"), p.Kind, fmt.Sprintf("not checked kind for apiVerion %s", p.APIVersion)))
		}
		allErrs = append(allErrs, metav1validation.ValidateLabels(p.MatchLabels, pathRoot.Child("matchLabels"))...)
		for _, namespaceName := range p.NamespaceNames {
			if !slices.Contains([]string{"default", "kube-public", "kube-node-lease"}, namespaceName) {
				allErrs = append(allErrs, field.Invalid(pathRoot.Child("namespaceNames"), namespaceName, "must be one of 'default', 'kube-public' or 'kube-node-lease'"))
			}
		}
		if !slices.Contains(rule.Statuses(), rule.Status(p.Status)) && len(p.Status) > 0 {
			allErrs = append(allErrs, field.Invalid(pathRoot.Child("status"), p.Status, "must be a valid status"))
		}
	}
	return allErrs
}

func (r *Rule242383) ID() string {
	return ID242383
}

func (r *Rule242383) Name() string {
	return "Kubernetes must separate user functionality (MEDIUM 242383)"
}

func (r *Rule242383) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}
	systemNamespaces := []string{"default", "kube-public", "kube-node-lease"}
	acceptedResources := []AcceptedResources242383{
		{
			// The 'kubernetes' Service is a required system resource exposing the kubernetes API server
			SelectResource: SelectResource{
				APIVersion: "v1",
				Kind:       "Service",
				MatchLabels: map[string]string{
					"component": "apiserver",
					"provider":  "kubernetes",
				},
				NamespaceNames: []string{"default"},
			},
			Status: "Passed",
		},
	}

	if r.Options != nil && r.Options.AcceptedResources != nil {
		acceptedResources = append(acceptedResources, r.Options.AcceptedResources...)
	}

	notDikiPodReq, err := labels.NewRequirement(pod.LabelComplianceRoleKey, selection.NotEquals, []string{pod.LabelComplianceRolePrivPod})
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
	}
	selector := labels.NewSelector().Add(*notDikiPodReq)

	for _, namespace := range systemNamespaces {
		partialMetadata, err := kubeutils.GetAllObjectsMetadata(ctx, r.Client, namespace, selector, 300)
		if err != nil {
			return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("namespace", namespace, "kind", "allList"))), nil
		}

		for _, p := range partialMetadata {
			target := rule.NewTarget("name", p.Name, "namespace", p.Namespace, "kind", p.Kind)

			acceptedIdx := slices.IndexFunc(acceptedResources, func(acceptedResource AcceptedResources242383) bool {
				return (p.APIVersion == acceptedResource.SelectResource.APIVersion) &&
					(acceptedResource.SelectResource.Kind == "*" || p.Kind == acceptedResource.SelectResource.Kind) &&
					slices.Contains(acceptedResource.SelectResource.NamespaceNames, namespace) &&
					utils.MatchLabels(p.Labels, acceptedResource.SelectResource.MatchLabels)
			})

			if acceptedIdx < 0 {
				checkResults = append(checkResults, rule.FailedCheckResult("Found user resource in system namespaces.", target))
				continue
			}

			acceptedResource := acceptedResources[acceptedIdx]

			msg := strings.TrimSpace(acceptedResource.Justification)
			status := strings.TrimSpace(acceptedResource.Status)
			switch status {
			case "Passed", "passed":
				if len(msg) == 0 {
					msg = "System resource in system namespaces."
				}
				checkResults = append(checkResults, rule.PassedCheckResult(msg, target))
			case "Accepted", "accepted", "":
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
