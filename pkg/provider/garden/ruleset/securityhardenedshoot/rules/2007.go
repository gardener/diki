// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	_ rule.Rule     = &Rule2007{}
	_ rule.Severity = &Rule2007{}
)

type Rule2007 struct {
	Client         client.Client
	ShootName      string
	ShootNamespace string
}

func (r *Rule2007) ID() string {
	return "2007"
}

func (r *Rule2007) Name() string {
	return "Shoot clusters must have a PodSecurity admission plugin configured."
}

func (r *Rule2007) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule2007) Run(ctx context.Context) (rule.RuleResult, error) {
	shoot := &gardencorev1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.FailedCheckResult(err.Error(), rule.NewTarget("name", r.ShootName, "namespace", r.ShootNamespace, "kind", "Shoot"))), nil
	}

}
