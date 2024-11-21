// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	"github.com/Masterminds/semver/v3"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	versionutils "github.com/gardener/gardener/pkg/utils/version"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule2006{}
	_ rule.Severity = &Rule2006{}
)

type Rule2006 struct {
	Client         client.Client
	ShootName      string
	ShootNamespace string
}

func (r *Rule2006) ID() string {
	return "2006"
}

func (r *Rule2006) Name() string {
	return "Shoot clusters must have static token kubeconfig disabled."
}

func (r *Rule2006) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule2006) Run(ctx context.Context) (rule.RuleResult, error) {
	shoot := &gardencorev1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", r.ShootName, "namespace", r.ShootNamespace, "kind", "Shoot"))), nil
	}

	version, err := semver.NewVersion(shoot.Spec.Kubernetes.Version)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
	}

	if versionutils.ConstraintK8sGreaterEqual127.Check(version) {
		return rule.Result(r, rule.PassedCheckResult("Static token kubeconfig is locked to disabled for the shoot (Kubernetes version >= 1.27).", rule.NewTarget())), nil
	}
	if shoot.Spec.Kubernetes.EnableStaticTokenKubeconfig == nil {
		return rule.Result(r, rule.PassedCheckResult("Static token kubeconfig is not enabled for the shoot.", rule.NewTarget())), nil
	}
	if !(*shoot.Spec.Kubernetes.EnableStaticTokenKubeconfig) {
		return rule.Result(r, rule.PassedCheckResult("Static token kubeconfig is disabled for the shoot.", rule.NewTarget())), nil
	}

	return rule.Result(r, rule.FailedCheckResult("Static token kubeconfig is enabled for the shoot.", rule.NewTarget())), nil
}
