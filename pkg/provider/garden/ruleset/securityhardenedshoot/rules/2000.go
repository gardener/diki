// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule2000{}
	_ rule.Severity = &Rule2000{}
)

type Rule2000 struct {
	Client         client.Client
	ShootName      string
	ShootNamespace string
}

func (r *Rule2000) ID() string {
	return "2000"
}

func (r *Rule2000) Name() string {
	return "Shoot clusters must have anonymous authentication disabled for the Kubernetes API server."
}

func (r *Rule2000) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule2000) Run(ctx context.Context) (rule.RuleResult, error) {
	shoot := &gardencorev1beta1.Shoot{ObjectMeta: v1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", r.ShootName, "namespace", r.ShootNamespace, "kind", "Shoot"))), nil
	}

	switch {
	//EnableAnonymousAuthentication is deprecated but still used in the Gardener API
	case shoot.Spec.Kubernetes.KubeAPIServer == nil || shoot.Spec.Kubernetes.KubeAPIServer.EnableAnonymousAuthentication == nil: //nolint:staticcheck
		return rule.Result(r, rule.PassedCheckResult("Anonymous authentication is not enabled.", rule.NewTarget())), nil
	case *shoot.Spec.Kubernetes.KubeAPIServer.EnableAnonymousAuthentication: //nolint:staticcheck
		return rule.Result(r, rule.FailedCheckResult("Anonymous authentication is enabled for the kube-apiserver.", rule.NewTarget())), nil
	default:
		return rule.Result(r, rule.PassedCheckResult("Anonymous authentication is disabled for the kube-apiserver.", rule.NewTarget())), nil
	}
}
