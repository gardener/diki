// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule2004{}
	_ rule.Severity = &Rule2004{}
)

type Rule2004 struct {
	Client         client.Client
	ShootName      string
	ShootNamespace string
}

func (r *Rule2004) ID() string {
	return "2004"
}

func (r *Rule2004) Name() string {
	return "Shoot clusters must have ValidatingAdmissionWebhook admission plugin enabled."
}

func (r *Rule2004) Severity() rule.SeverityLevel {
	return rule.SeverityHigh
}

func (r *Rule2004) Run(ctx context.Context) (rule.RuleResult, error) {
	shoot := &gardencorev1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", r.ShootName, "namespace", r.ShootNamespace, "kind", "Shoot"))), nil
	}

	if shoot.Spec.Kubernetes.KubeAPIServer == nil || shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins == nil {
		return rule.Result(r, rule.PassedCheckResult("The ValidatingAdmissionWebhook admission plugin is not disabled.", rule.NewTarget())), nil
	}

	var admissionPlugins = shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins

	// The ValidatingadmissionWebhook is required to be enabled by Kubernetes, and there isn't a known way to manually disable it.
	// Therefore, this rule check is always expected to pass.
	enabledIdx := slices.IndexFunc(admissionPlugins, func(plugin gardencorev1beta1.AdmissionPlugin) bool {
		return plugin.Name == "ValidatingAdmissionWebhook" && plugin.Disabled != nil && !*plugin.Disabled
	})
	disabledIdx := slices.IndexFunc(admissionPlugins, func(plugin gardencorev1beta1.AdmissionPlugin) bool {
		return plugin.Name == "ValidatingAdmissionWebhook" && plugin.Disabled != nil && *plugin.Disabled
	})
	if disabledIdx >= 0 {
		return rule.Result(r, rule.FailedCheckResult("The ValidatingAdmissionWebhook admission plugin is disabled.", rule.NewTarget())), nil
	}
	if enabledIdx >= 0 {
		return rule.Result(r, rule.PassedCheckResult("The ValidatingAdmissionWebhook admission plugin is enabled.", rule.NewTarget())), nil
	}

	return rule.Result(r, rule.PassedCheckResult("The ValidatingAdmissionWebhook admission plugin is not disabled.", rule.NewTarget())), nil
}
