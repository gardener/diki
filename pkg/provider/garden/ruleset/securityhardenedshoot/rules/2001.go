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
	_ rule.Rule     = &Rule2001{}
	_ rule.Severity = &Rule2001{}
)

type Rule2001 struct {
	Client         client.Client
	ShootName      string
	ShootNamespace string
}

func (r *Rule2001) ID() string {
	return "2001"
}

func (r *Rule2001) Name() string {
	return "Shoot clusters must disable ssh access to worker nodes."
}

func (r *Rule2001) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule2001) Run(ctx context.Context) (rule.RuleResult, error) {
	shoot := &gardencorev1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", r.ShootName, "namespace", r.ShootNamespace, "kind", "Shoot"))), nil
	}

	var checkResults []rule.CheckResult
	switch {
	case shoot.Spec.Provider.WorkersSettings == nil || shoot.Spec.Provider.WorkersSettings.SSHAccess == nil:
		checkResults = append(checkResults, rule.FailedCheckResult("Provider config doesn't disable SSH access to the worker nodes.", rule.NewTarget()))
	case !shoot.Spec.Provider.WorkersSettings.SSHAccess.Enabled:
		checkResults = append(checkResults, rule.PassedCheckResult("Provider config disables SSH access to the worker nodes", rule.NewTarget()))
	default:
		checkResults = append(checkResults, rule.FailedCheckResult("Provider config explicitly enables SSH access to the worker nodes.", rule.NewTarget()))
	}
	return rule.Result(r, checkResults...), nil
}
