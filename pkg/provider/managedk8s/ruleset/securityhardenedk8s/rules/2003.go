// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	_ rule.Rule     = &Rule2003{}
	_ rule.Severity = &Rule2003{}
)

type Rule2003 struct {
	Client client.Client
}

func (r *Rule2003) ID() string {
	return "2003"
}

func (r *Rule2003) Name() string {
	return "Pods should use only allowed volume types."
}

func (r *Rule2003) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule2003) Run(ctx context.Context) (rule.RuleResult, error) {
	allNamespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "namespaceList"))), nil
	}

	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "podList"))), nil
	}

	var checkResults []rule.CheckResult

	for _, pod := range pods {
		podTarget := rule.NewTarget("kind", "pod", "name", pod.Name, "namespace", pod.Namespace)
		for _, volume := range pod.Spec.Volumes {
			if volume.ConfigMap == nil && volume.CSI == nil && volume.DownwardAPI == nil &&
				volume.EmptyDir == nil && volume.Ephemeral == nil && volume.PersistentVolumeClaim == nil && volume.Projected == nil && volume.Secret == nil {
				checkResults = append(checkResults, rule.FailedCheckResult("Pod volume type is not within the accepted types.", podTarget.With("volume", volume.Name)))
			} else {
				checkResults = append(checkResults, rule.PassedCheckResult("Pod volume type is not within the accepted types.", podTarget.With("volume", volume.Name)))
			}
		}
	}

	return rule.Result(r, checkResults...), nil
}
