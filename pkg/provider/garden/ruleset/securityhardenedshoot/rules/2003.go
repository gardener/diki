// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule2003{}

type Rule2003 struct {
	Client         client.Client
	ShootName      string
	ShootNamespace string
}

func (r *Rule2003) ID() string {
	return "2003"
}

func (r *Rule2003) Name() string {
	return "Shoot clusters must enable kernel protection for Kubelets."
}

func (r *Rule2003) Run(ctx context.Context) (rule.RuleResult, error) {
	shoot := &gardencorev1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", r.ShootName, "namespace", r.ShootNamespace, "kind", "Shoot"))), nil
	}

	var checkResults []rule.CheckResult
	if shoot.Spec.Kubernetes.Kubelet == nil || shoot.Spec.Kubernetes.Kubelet.ProtectKernelDefaults == nil {
		checkResults = append(checkResults, rule.PassedCheckResult("Default kubelet config does not disable kernel protection.", rule.NewTarget()))
	} else if *shoot.Spec.Kubernetes.Kubelet.ProtectKernelDefaults {
		checkResults = append(checkResults, rule.PassedCheckResult("Default kubelet config enables kernel protection.", rule.NewTarget()))
	} else {
		checkResults = append(checkResults, rule.FailedCheckResult("Default kubelet config disables kernel protection.", rule.NewTarget()))
	}

	for _, w := range shoot.Spec.Provider.Workers {
		workerTarget := rule.NewTarget("worker", w.Name)
		if w.Kubernetes == nil || w.Kubernetes.Kubelet == nil || w.Kubernetes.Kubelet.ProtectKernelDefaults == nil {
			checkResults = append(checkResults, rule.PassedCheckResult("Worker kubelet config does not disable kernel protection.", workerTarget))
		} else if *w.Kubernetes.Kubelet.ProtectKernelDefaults {
			checkResults = append(checkResults, rule.PassedCheckResult("Worker kubelet config enables kernel protection.", workerTarget))
		} else {
			checkResults = append(checkResults, rule.FailedCheckResult("Worker kubelet config disables kernel protection.", workerTarget))
		}
	}

	return rule.Result(r, checkResults...), nil
}
