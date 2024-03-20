// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
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

var _ rule.Rule = &Rule242417{}

type Rule242417 struct {
	Client  client.Client
	Options *Options242417
}

type Options242417 struct {
	AcceptedPods []AcceptedPods242417 `json:"acceptedPods" yaml:"acceptedPods"`
}

type AcceptedPods242417 struct {
	PodMatchLabels map[string]string `json:"podMatchLabels" yaml:"podMatchLabels"`
	NamespaceNames []string          `json:"namespaceNames" yaml:"namespaceNames"`
	Justification  string            `json:"justification" yaml:"justification"`
	Status         string            `json:"status" yaml:"status"`
}

func (o Options242417) Validate() field.ErrorList {
	var (
		allErrs  field.ErrorList
		rootPath = field.NewPath("acceptedPods")
	)
	for _, p := range o.AcceptedPods {
		allErrs = append(allErrs, metav1validation.ValidateLabels(p.PodMatchLabels, rootPath.Child("podMatchLabels"))...)
		for _, namespaceName := range p.NamespaceNames {
			if !slices.Contains([]string{"kube-system", "kube-public", "kube-node-lease"}, namespaceName) {
				allErrs = append(allErrs, field.Invalid(rootPath.Child("namespaceNames"), namespaceName, "must be one of 'kube-system', 'kube-public' or 'kube-node-lease'"))
			}
		}
		if !slices.Contains(rule.Statuses(), rule.Status(p.Status)) && len(p.Status) > 0 {
			allErrs = append(allErrs, field.Invalid(rootPath.Child("status"), p.Status, "must be a valid status"))
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
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
	}
	selector := labels.NewSelector().Add(*notDikiPodReq)

	for _, namespace := range systemNamespaces {
		podsPartialMetadata, err := kubeutils.GetObjectsMetadata(ctx, r.Client, corev1.SchemeGroupVersion.WithKind("PodList"), namespace, selector, 300)
		if err != nil {
			return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("namespace", namespace, "kind", "podList"))), nil
		}

		for _, podPartialMetadata := range podsPartialMetadata {
			target := rule.NewTarget("name", podPartialMetadata.Name, "namespace", podPartialMetadata.Namespace, "kind", "pod")

			acceptedPodIdx := slices.IndexFunc(acceptedPods, func(acceptedPod AcceptedPods242417) bool {
				return slices.Contains(acceptedPod.NamespaceNames, namespace) &&
					utils.MatchLabels(podPartialMetadata.Labels, acceptedPod.PodMatchLabels)
			})

			if acceptedPodIdx < 0 {
				checkResults = append(checkResults, rule.FailedCheckResult("Found user pods in system namespaces.", target))
				continue
			}

			acceptedPod := r.Options.AcceptedPods[acceptedPodIdx]

			msg := strings.TrimSpace(acceptedPod.Justification)
			status := strings.TrimSpace(acceptedPod.Status)
			switch status {
			case "Passed", "passed":
				if len(msg) == 0 {
					msg = "System pod in system namespaces."
				}
				checkResults = append(checkResults, rule.PassedCheckResult(msg, target))
			case "Accepted", "accepted", "":
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
