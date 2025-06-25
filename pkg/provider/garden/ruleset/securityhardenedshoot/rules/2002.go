// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
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
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), kubeutils.TargetWithK8sObject(rule.NewTarget(), metav1.TypeMeta{Kind: "Shoot"}, shoot.ObjectMeta))), nil
	}

	var (
		kubernetesSpec    = shoot.Spec.Kubernetes
		featureGate       = "AllAlpha"
		components        = []string{"kube-apiserver", "kube-controller-manager", "kube-scheduler", "kube-proxy", "kubelet"}
		featureGateValues = make(map[string]bool)
	)

	if kubernetesSpec.KubeAPIServer != nil {
		if v, ok := kubernetesSpec.KubeAPIServer.FeatureGates[featureGate]; ok {
			featureGateValues["kube-apiserver"] = v
		}
	}

	if kubernetesSpec.KubeControllerManager != nil {
		if v, ok := kubernetesSpec.KubeControllerManager.FeatureGates[featureGate]; ok {
			featureGateValues["kube-controller-manager"] = v
		}
	}

	if kubernetesSpec.KubeScheduler != nil {
		if v, ok := kubernetesSpec.KubeScheduler.FeatureGates[featureGate]; ok {
			featureGateValues["kube-scheduler"] = v
		}
	}

	if kubernetesSpec.KubeProxy != nil {
		if v, ok := kubernetesSpec.KubeProxy.FeatureGates[featureGate]; ok {
			featureGateValues["kube-proxy"] = v
		}
	}

	if kubernetesSpec.Kubelet != nil {
		if v, ok := kubernetesSpec.Kubelet.FeatureGates[featureGate]; ok {
			featureGateValues["kubelet"] = v
		}
	}

	var checkResults []rule.CheckResult
	for _, component := range components {
		if v, ok := featureGateValues[component]; !ok {
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("AllAlpha featureGate is not enabled for the %s.", component), rule.NewTarget()))
		} else if v {
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("AllAlpha featureGate is enabled for the %s.", component), rule.NewTarget()))
		} else {
			checkResults = append(checkResults, rule.PassedCheckResult(fmt.Sprintf("AllAlpha featureGate is disabled for the %s.", component), rule.NewTarget()))
		}
	}

	for _, worker := range shoot.Spec.Provider.Workers {
		workerTarget := rule.NewTarget("worker", worker.Name)
		if worker.Kubernetes == nil || worker.Kubernetes.Kubelet == nil || worker.Kubernetes.Kubelet.FeatureGates == nil {
			checkResults = append(checkResults, rule.PassedCheckResult("AllAlpha featureGate is not enabled for the kubelet.", workerTarget))
			continue
		}
		if v, ok := worker.Kubernetes.Kubelet.FeatureGates[featureGate]; !ok {
			checkResults = append(checkResults, rule.PassedCheckResult("AllAlpha featureGate is not enabled for the kubelet.", workerTarget))
		} else if v {
			checkResults = append(checkResults, rule.FailedCheckResult("AllAlpha featureGate is enabled for the kubelet.", workerTarget))
		} else {
			checkResults = append(checkResults, rule.PassedCheckResult("AllAlpha featureGate is disabled for the kubelet.", workerTarget))
		}
	}

	return rule.Result(r, checkResults...), nil
}
