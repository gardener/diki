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

var (
	_ rule.Rule     = &Rule2005{}
	_ rule.Severity = &Rule2005{}
)

type Rule2005 struct {
	Client         client.Client
	ShootName      string
	ShootNamespace string
}

func (r *Rule2005) ID() string {
	return "2005"
}

func (r *Rule2005) Name() string {
	return "Shoot clusters must not disable timeouts for Kubelet."
}

func (r *Rule2005) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule2005) Run(ctx context.Context) (rule.RuleResult, error) {
	shoot := &gardencorev1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
	}

	var checkResults = []rule.CheckResult{}

	if shoot.Spec.Kubernetes.Kubelet == nil || shoot.Spec.Kubernetes.Kubelet.StreamingConnectionIdleTimeout == nil {
		checkResults = append(checkResults, rule.PassedCheckResult("The connection timeout is set to the reccomended value (5m).", rule.NewTarget()))
	} else {
		timeoutDuration := *shoot.Spec.Kubernetes.Kubelet.StreamingConnectionIdleTimeout
		switch {
		case timeoutDuration.Minutes() < 5:
			checkResults = append(checkResults, rule.FailedCheckResult("The connection timeout is not set to a valid value (< 5m).", rule.NewTarget()))
		case timeoutDuration.Minutes() == 5:
			checkResults = append(checkResults, rule.PassedCheckResult("The connection timeout is set to the reccomended value (5m).", rule.NewTarget()))
		case timeoutDuration.Hours() <= 4:
			checkResults = append(checkResults, rule.PassedCheckResult("The connection timeout is set to a valid value ([5m; 4h]).", rule.NewTarget()))
		default:
			checkResults = append(checkResults, rule.FailedCheckResult("The connection timeout is not set to a valid value (> 4h).", rule.NewTarget()))
		}
	}

	for _, worker := range shoot.Spec.Provider.Workers {
		workerTarget := rule.NewTarget("worker", worker.Name)
		if worker.Kubernetes == nil || worker.Kubernetes.Kubelet == nil || worker.Kubernetes.Kubelet.StreamingConnectionIdleTimeout == nil {
			checkResults = append(checkResults, rule.PassedCheckResult("The connection timeout is set to the reccomended value (5m).", workerTarget))
		} else {
			timeoutDuration := *worker.Kubernetes.Kubelet.StreamingConnectionIdleTimeout
			switch {
			case timeoutDuration.Minutes() < 5:
				checkResults = append(checkResults, rule.FailedCheckResult("The connection timeout is not set to a valid value (< 5m).", workerTarget))
			case timeoutDuration.Minutes() == 5:
				checkResults = append(checkResults, rule.PassedCheckResult("The connection timeout is set to the reccomended value (5m).", workerTarget))
			case timeoutDuration.Hours() <= 4:
				checkResults = append(checkResults, rule.PassedCheckResult("The connection timeout is set to a valid value ([5m; 4h]).", workerTarget))
			default:
				checkResults = append(checkResults, rule.FailedCheckResult("The connection timeout is not set to a valid value (> 4h).", workerTarget))
			}
		}
	}

	return rule.Result(r, checkResults...), nil
}
