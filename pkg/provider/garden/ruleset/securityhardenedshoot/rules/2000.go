// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"slices"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
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
	Options        *Options2000
}

type Options2000 struct {
	AllowedEndpoints []AllowedEndpoint `yaml:"allowedEndpoints" json:"allowedEndpoints"`
}

type AllowedEndpoint struct {
	Path string `yaml:"path" json:"path"`
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
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), kubeutils.TargetWithK8sObject(rule.NewTarget(), v1.TypeMeta{Kind: "Shoot"}, shoot.ObjectMeta))), nil
	}

	if shoot.Spec.Kubernetes.KubeAPIServer == nil {
		return rule.Result(r, rule.PassedCheckResult("Anonymous authentication is not enabled for the kube-apiserver.", rule.NewTarget())), nil
	}

	// TODO (georgibaltiev): remove any references to the EnableAnonymousAuthentication field after it's removal
	if shoot.Spec.Kubernetes.KubeAPIServer.EnableAnonymousAuthentication != nil { //nolint:staticcheck
		if *shoot.Spec.Kubernetes.KubeAPIServer.EnableAnonymousAuthentication { //nolint:staticcheck
			return rule.Result(r, rule.FailedCheckResult("Anonymous authentication is enabled for the kube-apiserver.", rule.NewTarget())), nil
		}
		return rule.Result(r, rule.PassedCheckResult("Anonymous authentication is disabled for the kube-apiserver.", rule.NewTarget())), nil
	}

	if shoot.Spec.Kubernetes.KubeAPIServer.StructuredAuthentication == nil {
		return rule.Result(r, rule.PassedCheckResult("Anonymous authentication is not enabled for the kube-apiserver.", rule.NewTarget())), nil
	}

	var (
		fileName        = "config.yaml"
		configMapName   = shoot.Spec.Kubernetes.KubeAPIServer.StructuredAuthentication.ConfigMapName
		configMap       = &corev1.ConfigMap{ObjectMeta: v1.ObjectMeta{Name: configMapName, Namespace: r.ShootNamespace}}
		configMapTarget = kubeutils.TargetWithK8sObject(rule.NewTarget(), v1.TypeMeta{Kind: "ConfigMap"}, configMap.ObjectMeta)
	)

	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(configMap), configMap); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), configMapTarget)), nil
	}

	authConfigString, ok := configMap.Data[fileName]
	if !ok {
		return rule.Result(r, rule.ErroredCheckResult(fmt.Sprintf("configMap: %s does not contain field: %s in Data field", configMapName, fileName), configMapTarget)), nil
	}

	authenticationConfig := &apiserverv1beta1.AuthenticationConfiguration{}
	if err := yaml.Unmarshal([]byte(authConfigString), authenticationConfig); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), configMapTarget)), nil
	}

	switch {
	case authenticationConfig.Anonymous == nil:
		return rule.Result(r, rule.PassedCheckResult("Anonymous authentication is not enabled for the kube-apiserver.", configMapTarget)), nil
	case authenticationConfig.Anonymous.Enabled:
		if r.Options == nil || len(authenticationConfig.Anonymous.Conditions) == 0 {
			return rule.Result(r, rule.FailedCheckResult("Anonymous authentication is enabled for the kube-apiserver.", configMapTarget)), nil
		}

		var checkResults []rule.CheckResult

		for _, condition := range authenticationConfig.Anonymous.Conditions {
			if !slices.ContainsFunc(r.Options.AllowedEndpoints, func(allowedPath AllowedEndpoint) bool {
				return allowedPath.Path == condition.Path
			}) {
				checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Anonymous authentication is not allowed for endpoint %s of the kube-apiserver.", condition.Path), configMapTarget))
			}
		}

		if len(checkResults) == 0 {
			return rule.Result(r, rule.AcceptedCheckResult("Anonymous authentication is allowed for the specified endpoints of the kube-apiserver.", configMapTarget)), nil
		}
		return rule.Result(r, checkResults...), nil
	default:
		return rule.Result(r, rule.PassedCheckResult("Anonymous authentication is disabled for the kube-apiserver.", configMapTarget)), nil
	}
}
