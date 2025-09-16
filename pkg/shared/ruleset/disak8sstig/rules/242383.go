// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule     = &Rule242383{}
	_ rule.Severity = &Rule242383{}
)

type Rule242383 struct {
	Client  client.Client
	Options *Options242383
}

type Options242383 struct {
	AcceptedResources []AcceptedResources242383 `json:"acceptedResources" yaml:"acceptedResources"`
}

var _ option.Option = (*Options242383)(nil)

type AcceptedResources242383 struct {
	AcceptedObjectSelector
	Status string `json:"status" yaml:"status"`
}

func (o Options242383) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs               field.ErrorList
		acceptedResourcesPath = fldPath.Child("acceptedResources")
	)
	for idx, r := range o.AcceptedResources {
		allErrs = append(allErrs, r.Validate(acceptedResourcesPath.Index(idx))...)
		if !slices.Contains([]string{"Passed", "Accepted"}, r.Status) && len(r.Status) > 0 {
			allErrs = append(allErrs, field.Invalid(acceptedResourcesPath.Index(idx).Child("status"), r.Status, "must be one of 'Passed' or 'Accepted'"))
		}
	}
	return allErrs
}

type AcceptedObjectSelector struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind" yaml:"kind"`
	option.AcceptedNamespacedObject
}

var _ option.Option = (*AcceptedObjectSelector)(nil)

func (s AcceptedObjectSelector) Validate(fldPath *field.Path) field.ErrorList {
	var (
		allErrs          field.ErrorList
		checkedResources = map[string][]string{
			"v1":             {"Pod", "ReplicationController", "Service"},
			"apps/v1":        {"Deployment", "DaemonSet", "ReplicaSet", "StatefulSet"},
			"batch/v1":       {"Job", "CronJob"},
			"autoscaling/v1": {"HorizontalPodAutoscaler"},
		}
	)

	if kinds, ok := checkedResources[s.APIVersion]; !ok {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("apiVersion"), s.APIVersion, "not checked apiVersion"))
	} else if !slices.Contains(kinds, s.Kind) && s.Kind != "*" {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("kind"), s.Kind, fmt.Sprintf("not checked kind for apiVersion %s", s.APIVersion)))
	}

	allErrs = append(allErrs, s.AcceptedNamespacedObject.Validate(fldPath)...)

	return allErrs
}

func (r *Rule242383) ID() string {
	return ID242383
}

func (r *Rule242383) Name() string {
	return "Kubernetes must separate user functionality."
}

func (r *Rule242383) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242383) Run(ctx context.Context) (rule.RuleResult, error) {
	allNamespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
	}

	var (
		checkResults      []rule.CheckResult
		systemNamespaces  = []string{"default", "kube-public", "kube-node-lease"}
		acceptedResources = []AcceptedResources242383{
			{
				// The 'kubernetes' Service is a required system resource exposing the kubernetes API server
				AcceptedObjectSelector: AcceptedObjectSelector{
					APIVersion: "v1",
					Kind:       "Service",
					AcceptedNamespacedObject: option.AcceptedNamespacedObject{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"component": "apiserver",
									"provider":  "kubernetes",
								},
							},
							NamespaceLabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"kubernetes.io/metadata.name": "default"},
							},
						},
					},
				},
				Status: "Passed",
			},
		}
		isPartOf = func(ownerRefs []metav1.OwnerReference, partialMetadata []metav1.PartialObjectMetadata) bool {
			for _, ownerRef := range ownerRefs {
				if slices.ContainsFunc(partialMetadata, func(p metav1.PartialObjectMetadata) bool {
					return ownerRef.UID == p.UID
				}) {
					return true
				}
			}
			return false
		}
	)

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
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("namespace", namespace, "kind", "AllList"))), nil
		}
		for _, p := range partialMetadata {
			// Skip when owners reference of objects is checked
			if isPartOf(p.OwnerReferences, partialMetadata) {
				continue
			}

			var (
				accepted    bool
				msg, status string
				target      = kubeutils.TargetWithK8sObject(rule.NewTarget(), p.TypeMeta, p.ObjectMeta)
			)

			for _, acceptedResource := range acceptedResources {
				if matches, err := acceptedResource.Matches(p.Labels, allNamespaces[namespace].Labels); err != nil {
					return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), err
				} else if matches && p.APIVersion == acceptedResource.APIVersion &&
					(acceptedResource.Kind == "*" || p.Kind == acceptedResource.Kind) {
					accepted = true
					msg = strings.TrimSpace(acceptedResource.Justification)
					status = strings.TrimSpace(acceptedResource.Status)
					break
				}
			}

			if !accepted {
				checkResults = append(checkResults, rule.FailedCheckResult("Found user resource in system namespaces.", target))
				continue
			}

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

	return rule.Result(r, checkResults...), nil
}
