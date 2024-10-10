// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
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

var _ rule.Rule = &Rule242417{}

type Rule242417 struct {
	Client  client.Client
	Options *Options242417
}

type Options242417 struct {
	AcceptedPods []AcceptedPods242417 `json:"acceptedPods" yaml:"acceptedPods"`
}

var _ option.Option = (*Options242417)(nil)

type AcceptedPods242417 struct {
	option.PodAttributesLabels
	Justification string `json:"justification" yaml:"justification"`
	Status        string `json:"status" yaml:"status"`
}

func (o Options242417) Validate() field.ErrorList {
	var (
		allErrs  field.ErrorList
		rootPath = field.NewPath("acceptedPods")
	)

	for _, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate()...)
		if !slices.Contains([]string{"Passed", "Accepted"}, p.Status) && len(p.Status) > 0 {
			allErrs = append(allErrs, field.Invalid(rootPath.Child("status"), p.Status, "must be one of 'Passed' or 'Accepted'"))
		}
	}

	return allErrs
}

func (r *Rule242417) ID() string {
	return ID242417
}

func (r *Rule242417) Name() string {
	return "Kubernetes must separate user functionality (MEDIUM 242417)"
}

func (r *Rule242417) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}
	systemNamespaces := []string{"kube-system", "kube-public", "kube-node-lease"}
	acceptedPods := []AcceptedPods242417{}

	if r.Options != nil && r.Options.AcceptedPods != nil {
		acceptedPods = r.Options.AcceptedPods
	}

	notDikiPodReq, err := labels.NewRequirement(pod.LabelComplianceRoleKey, selection.NotEquals, []string{pod.LabelComplianceRolePrivPod})

	if err != nil {
		return rule.SingleCheckResult(r, rule.CheckResult{Status: rule.Errored, Message: err.Error(), Target: rule.NewTarget()}), nil
	}

	selector := labels.NewSelector().Add(*notDikiPodReq)

	namespacesPartialMetadata, err := kubeutils.GetNamespaces(ctx, r.Client)

	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("", ""))), nil
	}

	for _, namespace := range systemNamespaces {

		podsPartialMetadata, err := kubeutils.GetObjectsMetadata(ctx, r.Client, corev1.SchemeGroupVersion.WithKind("PodList"), namespace, selector, 300)

		if err != nil {
			return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("namespace", namespace, "kind", "podList"))), nil
		}

		for _, podPartialMetadata := range podsPartialMetadata {
			target := rule.NewTarget("name", podPartialMetadata.Name, "namespace", podPartialMetadata.Namespace, "kind", "pod")

			acceptedPodIdx := slices.IndexFunc(acceptedPods, func(acceptedPod AcceptedPods242417) bool {
				return utils.MatchLabels(podPartialMetadata.Labels, acceptedPod.PodMatchLabels) && utils.MatchLabels(namespacesPartialMetadata[namespace].Labels, acceptedPod.NamespaceMatchLabels)
			})

			if acceptedPodIdx < 0 {
				checkResults = append(checkResults, rule.FailedCheckResult("Found user pods in system namespaces.", target))
				continue
			}

			acceptedPod := r.Options.AcceptedPods[acceptedPodIdx]

			msg := strings.TrimSpace(acceptedPod.Justification)
			status := strings.TrimSpace(acceptedPod.Status)
			switch status {
			case "Passed":
				if len(msg) == 0 {
					msg = "System pod in system namespaces."
				}
				checkResults = append(checkResults, rule.PassedCheckResult(msg, target))
			case "Accepted", "":
				if len(msg) == 0 {
					msg = "Accepted user pod in system namespaces."
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
