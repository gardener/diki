// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
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

	var (
		kubernetesSpec = shoot.Spec.Kubernetes
		allAlpha       = "AllAlpha"
		components     = []string{"kube apiserver", "kube controller manager", "kube scheduler", "kube proxy", "kubelet"}
	)

	allAlphaFeatureGatesValues := map[string]*bool{}

	allAlphaFeatureGatesValues["kube apiserver"] = func() *bool {
		if kubernetesSpec.KubeAPIServer != nil && kubernetesSpec.KubeAPIServer.FeatureGates != nil {
			return ptr.To(kubernetesSpec.KubeAPIServer.FeatureGates[allAlpha])
		}
		return nil
	}()

	allAlphaFeatureGatesValues["kube controller manager"] = func() *bool {
		if kubernetesSpec.KubeControllerManager != nil && kubernetesSpec.KubeControllerManager.FeatureGates != nil {
			return ptr.To(kubernetesSpec.KubeControllerManager.FeatureGates[allAlpha])
		}
		return nil
	}()

	allAlphaFeatureGatesValues["kube scheduler"] = func() *bool {
		if kubernetesSpec.KubeScheduler != nil && kubernetesSpec.KubeScheduler.FeatureGates != nil {
			return ptr.To(kubernetesSpec.KubeScheduler.FeatureGates[allAlpha])
		}
		return nil
	}()

	allAlphaFeatureGatesValues["kube proxy"] = func() *bool {
		if kubernetesSpec.KubeProxy != nil && kubernetesSpec.KubeProxy.FeatureGates != nil {
			return ptr.To(kubernetesSpec.KubeProxy.FeatureGates[allAlpha])
		}
		return nil
	}()

	allAlphaFeatureGatesValues["kubelet"] = func() *bool {
		if kubernetesSpec.Kubelet != nil && kubernetesSpec.Kubelet.FeatureGates != nil {
			return ptr.To(kubernetesSpec.Kubelet.FeatureGates[allAlpha])
		}
		return nil
	}()

	var checkResults []rule.CheckResult

	for _, component := range components {

		if allAlphaFeatureGatesValues[component] == nil {
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("AllAlpha featureGates are not enabled for the %s.", component), rule.NewTarget()))
		} else {
			if *(allAlphaFeatureGatesValues[component]) {
				checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("AllAlpha featureGates are enabled for the %s.", component), rule.NewTarget()))
			} else {
				checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("AllAlpha featureGates are disabled for the %s.", component), rule.NewTarget()))
			}
		}
	}

	return rule.Result(r, checkResults...), nil
}
