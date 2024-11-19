// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"time"

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
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", r.ShootName, "namespace", r.ShootNamespace, "kind", "Shoot"))), nil
	}

	var (
		checkResults            = []rule.CheckResult{}
		evaluateTimeoutDuration = func(timeoutDuration metav1.Duration, target rule.Target) rule.CheckResult {
			switch {
			case timeoutDuration.Duration < 5*time.Minute:
				return rule.FailedCheckResult("The connection timeout is set to a not allowed value (< 5m).", target)
			case timeoutDuration.Duration == 5*time.Minute:
				return rule.PassedCheckResult("The connection timeout is set to the recommended value (5m).", target)
			case timeoutDuration.Duration <= 4*time.Hour:
				return rule.PassedCheckResult("The connection timeout is set to an allowed, but not recommended value (should be 5m).", target)
			default:
				return rule.FailedCheckResult("The connection timeout is not set to an allowed value (> 4h).", target)
			}
		}
	)

	if shoot.Spec.Kubernetes.Kubelet == nil || shoot.Spec.Kubernetes.Kubelet.StreamingConnectionIdleTimeout == nil {
		checkResults = append(checkResults, rule.PassedCheckResult("The connection timeout is not set and therefore will be defaulted to the recommended value (5m).", rule.NewTarget()))
	} else {
		timeoutDuration := *shoot.Spec.Kubernetes.Kubelet.StreamingConnectionIdleTimeout
		checkResults = append(checkResults, evaluateTimeoutDuration(timeoutDuration, rule.NewTarget()))
	}

	for _, worker := range shoot.Spec.Provider.Workers {
		workerTarget := rule.NewTarget("worker", worker.Name)
		if worker.Kubernetes == nil || worker.Kubernetes.Kubelet == nil || worker.Kubernetes.Kubelet.StreamingConnectionIdleTimeout == nil {
			checkResults = append(checkResults, rule.PassedCheckResult("The connection timeout is not set and therefore will be defaulted to the recommended value (5m).", workerTarget))
		} else {
			timeoutDuration := *worker.Kubernetes.Kubelet.StreamingConnectionIdleTimeout
			checkResults = append(checkResults, evaluateTimeoutDuration(timeoutDuration, workerTarget))
		}
	}

	return rule.Result(r, checkResults...), nil
}
