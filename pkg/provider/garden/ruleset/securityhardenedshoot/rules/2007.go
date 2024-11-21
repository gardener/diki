// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"

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
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", r.ShootName, "namespace", r.ShootNamespace, "kind", "Shoot"))), nil
	}

	var podSecurityPlugin = "PodSecurity"

	if shoot.Spec.Kubernetes.KubeAPIServer == nil || shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins == nil {
		//enabled by default, but not clear how it's configured by default yet
	}

	if slices.ContainsFunc(shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins, func(admissionPlugin gardencorev1beta1.AdmissionPlugin) bool {
		return admissionPlugin.Name == podSecurityPlugin && admissionPlugin.Disabled != nil && *admissionPlugin.Disabled
	}) {
		return rule.Result(r, rule.FailedCheckResult("The PodSecurity admission plugin is disabled.", rule.NewTarget())), nil
	}

	enabledPodSecurityPluginIdx := slices.IndexFunc(shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins, func(admissionPlugin gardencorev1beta1.AdmissionPlugin) bool {
		return admissionPlugin.Name == podSecurityPlugin
	})

	if enabledPodSecurityPluginIdx < 0 {
		// default version, not clear how its enabled yet
	}

	var enabledPodSecurityPlugin = shoot.Spec.Kubernetes.KubeAPIServer.AdmissionPlugins[enabledPodSecurityPluginIdx]

	//evaluate the found match

}
