// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/kustomize/kyaml/yaml"

	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule2000{}
	_ rule.Severity = &Rule2000{}
)

const fileName = "config.yaml"

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

	if shoot.Spec.Kubernetes.KubeAPIServer == nil {
		return rule.Result(r, rule.PassedCheckResult("Anonymous authentication is not enabled for the kube-apiserver.", rule.NewTarget())), nil
	}

	// TODO (georgibaltiev): remove any references to the EnableAnonymousAuthentication field after it's deprecation
	if shoot.Spec.Kubernetes.KubeAPIServer.EnableAnonymousAuthentication != nil { //nolint:staticcheck
		if *shoot.Spec.Kubernetes.KubeAPIServer.EnableAnonymousAuthentication { //nolint:staticcheck
			return rule.Result(r, rule.FailedCheckResult("Anonymous authentication is enabled for the kube-apiserver.", rule.NewTarget())), nil
		}
		return rule.Result(r, rule.PassedCheckResult("Anonymous authentication is disabled for the kube-apiserver.", rule.NewTarget())), nil
	}

	if shoot.Spec.Kubernetes.KubeAPIServer.StructuredAuthentication == nil {
		return rule.Result(r, rule.PassedCheckResult("Anonymous authentication is not enabled for the kube-apiserver.", rule.NewTarget())), nil
	}

	configMapName := shoot.Spec.Kubernetes.KubeAPIServer.StructuredAuthentication.ConfigMapName
	configMap := &corev1.ConfigMap{ObjectMeta: v1.ObjectMeta{Name: configMapName, Namespace: r.ShootNamespace}}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(configMap), configMap); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", configMapName, "namespace", r.ShootNamespace, "kind", "ConfigMap"))), nil
	}

	authConfigString, ok := configMap.Data[fileName]
	if !ok {
		return rule.Result(r, rule.WarningCheckResult(fmt.Sprintf("The %s key is not present in the configMap.", fileName), rule.NewTarget("name", configMapName, "namespace", r.ShootNamespace, "kind", "ConfigMap"))), nil
	}

	authenticationConfig := &apiserverv1beta1.AuthenticationConfiguration{}
	if err := yaml.Unmarshal([]byte(authConfigString), authenticationConfig); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("name", configMapName, "namespace", r.ShootNamespace, "kind", "ConfigMap"))), nil
	}

	if authenticationConfig.Anonymous.Enabled {
		return rule.Result(r, rule.FailedCheckResult("Anonymous authentication is enabled for the kube-apiserver.", rule.NewTarget("name", configMapName, "namespace", r.ShootNamespace, "kind", "ConfigMap"))), nil
	}
	return rule.Result(r, rule.PassedCheckResult("Anonymous authentication is disabled for the kube-apiserver.", rule.NewTarget("name", configMapName, "namespace", r.ShootNamespace, "kind", "ConfigMap"))), nil
}
