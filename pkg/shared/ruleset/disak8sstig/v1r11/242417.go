// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"context"
	"fmt"

	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
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

	if r.Options != nil {
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
				return (len(acceptedPod.NamespaceNames) == 0 || slices.Contains(acceptedPod.NamespaceNames, namespace)) &&
					utils.MatchLabels(podPartialMetadata.Labels, acceptedPod.PodMatchLabels)
			})

			if acceptedPodIdx < 0 {
				checkResults = append(checkResults, rule.FailedCheckResult("Found user pods in system namespaces.", target))
				continue
			}

			acceptedPod := r.Options.AcceptedPods[acceptedPodIdx]

			msg := acceptedPod.Justification
			switch acceptedPod.Status {
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
				checkResults = append(checkResults, rule.ErroredCheckResult(fmt.Sprintf("unrecognized status set: %s", acceptedPod.Status), target))
			}
		}
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}
