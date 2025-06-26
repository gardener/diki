// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
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
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), kubeutils.TargetWithK8sObject(rule.NewTarget(), metav1.TypeMeta{Kind: "Shoot"}, shoot.ObjectMeta))), nil
	}

	switch {
	case shoot.Spec.Provider.WorkersSettings == nil || shoot.Spec.Provider.WorkersSettings.SSHAccess == nil:
		return rule.Result(r, rule.FailedCheckResult("SSH access is not disabled for worker nodes.", rule.NewTarget())), nil
	case !shoot.Spec.Provider.WorkersSettings.SSHAccess.Enabled:
		return rule.Result(r, rule.PassedCheckResult("SSH access is disabled for worker nodes.", rule.NewTarget())), nil
	default:
		return rule.Result(r, rule.FailedCheckResult("SSH access is enabled for worker nodes.", rule.NewTarget())), nil
	}
}
