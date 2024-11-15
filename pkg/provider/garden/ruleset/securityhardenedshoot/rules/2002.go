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
	_ rule.Rule     = &Rule2002{}
	_ rule.Severity = &Rule2002{}
)

type Rule2002 struct {
	Client         client.Client
	ShootName      string
	ShootNamespace string
}

func (r *Rule2002) ID() string {
	return "2002"
}

func (r *Rule2002) Name() string {
	return "Shoot clusters must not have Alpha APIs enabled for any Kubernetes component."
}

func (r *Rule2002) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule2002) Run(ctx context.Context) (rule.RuleResult, error) {
	shoot := &gardencorev1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Name: r.ShootName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(shoot), shoot); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "Shoot", "name", r.ShootName, "namespace", r.ShootNamespace))), nil
	}

	var checkResults []rule.CheckResult

	switch {
	case shoot.Spec.Kubernetes.KubeAPIServer == nil || shoot.Spec.Kubernetes.KubeAPIServer.FeatureGates == nil:
		checkResults = append(checkResults, rule.PassedCheckResult("AllAlpha featureGates are not enabled for the kube apiserver.", rule.NewTarget()))
	case shoot.Spec.Kubernetes.KubeAPIServer.FeatureGates["AllAlpha"]:
		checkResults = append(checkResults, rule.FailedCheckResult("AllAlpha featureGates are enabled for the kube apiserver.", rule.NewTarget()))
	default:
		checkResults = append(checkResults, rule.PassedCheckResult("AllAlpha featureGates are disabled for the kube apiserver.", rule.NewTarget()))
	}

	switch {
	case shoot.Spec.Kubernetes.KubeControllerManager == nil || shoot.Spec.Kubernetes.KubeControllerManager.FeatureGates == nil:
		checkResults = append(checkResults, rule.PassedCheckResult("AllAlpha featureGates are not enabled for the kube controller manager.", rule.NewTarget()))
	case shoot.Spec.Kubernetes.KubeControllerManager.FeatureGates["AllAlpha"]:
		checkResults = append(checkResults, rule.FailedCheckResult("AllAlpha featureGates are enabled for the kube controller manager.", rule.NewTarget()))
	default:
		checkResults = append(checkResults, rule.PassedCheckResult("AllAlpha featureGates are disabled for the kube controller manager.", rule.NewTarget()))
	}

	switch {
	case shoot.Spec.Kubernetes.KubeScheduler == nil || shoot.Spec.Kubernetes.KubeScheduler.FeatureGates == nil:
		checkResults = append(checkResults, rule.PassedCheckResult("AllAlpha featureGates are not enabled for the kube scheduler.", rule.NewTarget()))
	case shoot.Spec.Kubernetes.KubeScheduler.FeatureGates["AllAlpha"]:
		checkResults = append(checkResults, rule.FailedCheckResult("AllAlpha featureGates are enabled for the kube scheduler.", rule.NewTarget()))
	default:
		checkResults = append(checkResults, rule.PassedCheckResult("AllAlpha featureGates are disabled for the kube scheduler.", rule.NewTarget()))
	}

	switch {
	case shoot.Spec.Kubernetes.KubeProxy == nil || shoot.Spec.Kubernetes.KubeProxy.FeatureGates == nil:
		checkResults = append(checkResults, rule.PassedCheckResult("AllAlpha featureGates are not enabled for the kube proxy.", rule.NewTarget()))
	case shoot.Spec.Kubernetes.KubeProxy.FeatureGates["AllAlpha"]:
		checkResults = append(checkResults, rule.FailedCheckResult("AllAlpha featureGates are enabled for the kube proxy.", rule.NewTarget()))
	default:
		checkResults = append(checkResults, rule.PassedCheckResult("AllAlpha featureGates are disabled for the kube proxy.", rule.NewTarget()))
	}

	switch {
	case shoot.Spec.Kubernetes.Kubelet == nil || shoot.Spec.Kubernetes.Kubelet.FeatureGates == nil:
		checkResults = append(checkResults, rule.PassedCheckResult("AllAlpha featureGates are not enabled for the kubelet.", rule.NewTarget()))
	case shoot.Spec.Kubernetes.Kubelet.FeatureGates["AllAlpha"]:
		checkResults = append(checkResults, rule.FailedCheckResult("AllAlpha featureGates are enabled for the kubelet.", rule.NewTarget()))
	default:
		checkResults = append(checkResults, rule.PassedCheckResult("AllAlpha featureGates are disabled for the kubelet.", rule.NewTarget()))
	}

	return rule.Result(r, checkResults...), nil
}
