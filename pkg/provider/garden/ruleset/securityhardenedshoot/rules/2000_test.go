// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/garden/ruleset/securityhardenedshoot/rules"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#2000", func() {
	var (
		fakeClient     client.Client
		ctx            = context.TODO()
		shootName      = "foo"
		shootNamespace = "bar"

		authenticationConfigMap *corev1.ConfigMap

		shoot    *gardencorev1beta1.Shoot
		r        rule.Rule
		ruleName = "Shoot clusters must have anonymous authentication disabled for the Kubernetes API server."
		ruleID   = "2000"
		severity = rule.SeverityHigh
	)

	const (
		fileName                                              = "config.yaml"
		configMapName                                         = "authentication-config"
		invalidAnonymousAuthenticationConfig                  = "foo"
		disabledAnonymousAuthenticationConfig                 = "apiVersion: apiserver.config.k8s.io/v1beta1\nkind: AuthenticationConfiguration\nanonymous:\n  enabled: false"
		enabledAnonymousAuthenticationConfigWithConditions    = "apiVersion: apiserver.config.k8s.io/v1beta1\nkind: AuthenticationConfiguration\nanonymous:\n  enabled: true\n  conditions:\n  - path: /healthz\n  - path: /livez"
		enabledAnonymousAuthenticationConfigWithoutConditions = "apiVersion: apiserver.config.k8s.io/v1beta1\nkind: AuthenticationConfiguration\nanonymous:\n  enabled: true"
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.GardenScheme).Build()

		shoot = &gardencorev1beta1.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      shootName,
				Namespace: shootNamespace,
			},
		}

		authenticationConfigMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      configMapName,
				Namespace: shootNamespace,
			},
		}

		r = &rules.Rule2000{
			Client:         fakeClient,
			ShootName:      shootName,
			ShootNamespace: shootNamespace,
		}
	})

	// TODO (georgibaltiev): remove any references to the EnableAnonymousAuthentication field after it's deprecation
	DescribeTable("Run cases", func(updateFn func(), expectedCheckResult rule.CheckResult) {
		updateFn()
		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())
		res, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(Equal(rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: severity, CheckResults: []rule.CheckResult{expectedCheckResult}}))
	},
		Entry("should error when the shoot is not found",
			func() { shoot.Name = "notFoo" },
			rule.CheckResult{Status: rule.Errored, Message: "shoots.core.gardener.cloud \"foo\" not found", Target: rule.NewTarget("kind", "Shoot", "name", "foo", "namespace", "bar")},
		),
		Entry("should pass when kube-apiserver configuration is not set",
			func() {},
			rule.CheckResult{Status: rule.Passed, Message: "Anonymous authentication is not enabled for the kube-apiserver.", Target: rule.NewTarget()},
		),
		Entry("should pass when the enabledAnoymousAuthentication flag is set to false",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						EnableAnonymousAuthentication: ptr.To(false),
					},
				}
			},
			rule.CheckResult{Status: rule.Passed, Message: "Anonymous authentication is disabled for the kube-apiserver.", Target: rule.NewTarget()},
		),
		Entry("should fail the enabledAnoymousAuthentication flag is set to true",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						EnableAnonymousAuthentication: ptr.To(true),
					},
				}
			},
			rule.CheckResult{Status: rule.Failed, Message: "Anonymous authentication is enabled for the kube-apiserver.", Target: rule.NewTarget()},
		),
		Entry("should pass when neither the enableAnonymousAuthentication nor the structuredAuthenticaton flags are set",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						KubernetesConfig: gardencorev1beta1.KubernetesConfig{
							FeatureGates: map[string]bool{"foo": true},
						},
					},
				}
			},
			rule.CheckResult{Status: rule.Passed, Message: "Anonymous authentication is not enabled for the kube-apiserver.", Target: rule.NewTarget()},
		),
		Entry("should error if the structuredAuthentication configMap is not present",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						StructuredAuthentication: &gardencorev1beta1.StructuredAuthentication{
							ConfigMapName: configMapName,
						},
					},
				}
			},
			rule.CheckResult{Status: rule.Errored, Message: "configmaps \"authentication-config\" not found", Target: rule.NewTarget("name", configMapName, "namespace", shootNamespace, "kind", "ConfigMap")},
		),
		Entry("should warn if the structured authentication config does not contain a config.yaml key",
			func() {
				authenticationConfigMap.Data = map[string]string{
					"foo": "bar",
				}

				Expect(fakeClient.Create(ctx, authenticationConfigMap)).To(Succeed())

				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						StructuredAuthentication: &gardencorev1beta1.StructuredAuthentication{
							ConfigMapName: configMapName,
						},
					},
				}
			},
			rule.CheckResult{Status: rule.Errored, Message: "configMap: authentication-config does not contain field: config.yaml in Data field", Target: rule.NewTarget("name", configMapName, "namespace", shootNamespace, "kind", "ConfigMap")},
		),
		Entry("should error if the structuredAuthentication configMap contains an invalid value",
			func() {
				authenticationConfigMap.Data = map[string]string{
					fileName: invalidAnonymousAuthenticationConfig,
				}

				Expect(fakeClient.Create(ctx, authenticationConfigMap)).To(Succeed())

				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						StructuredAuthentication: &gardencorev1beta1.StructuredAuthentication{
							ConfigMapName: configMapName,
						},
					},
				}
			},
			rule.CheckResult{Status: rule.Errored, Message: "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `foo` into v1beta1.AuthenticationConfiguration", Target: rule.NewTarget("name", configMapName, "namespace", shootNamespace, "kind", "ConfigMap")},
		),
		Entry("should fail if the structuredAuthentication configuration has anonymous access enabled unconditionally",
			func() {
				authenticationConfigMap.Data = map[string]string{
					fileName: enabledAnonymousAuthenticationConfigWithoutConditions,
				}

				Expect(fakeClient.Create(ctx, authenticationConfigMap)).To(Succeed())

				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						StructuredAuthentication: &gardencorev1beta1.StructuredAuthentication{
							ConfigMapName: configMapName,
						},
					},
				}
			},
			rule.CheckResult{Status: rule.Failed, Message: "Anonymous authentication is enabled for the kube-apiserver.", Target: rule.NewTarget("name", configMapName, "namespace", shootNamespace, "kind", "ConfigMap")},
		),
		Entry("should fail if the structured authentication config has anonymous access enabled with conditions",
			func() {
				authenticationConfigMap.Data = map[string]string{
					fileName: enabledAnonymousAuthenticationConfigWithConditions,
				}

				Expect(fakeClient.Create(ctx, authenticationConfigMap)).To(Succeed())

				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						StructuredAuthentication: &gardencorev1beta1.StructuredAuthentication{
							ConfigMapName: configMapName,
						},
					},
				}
			},
			rule.CheckResult{Status: rule.Failed, Message: "Anonymous authentication is enabled for the kube-apiserver.", Target: rule.NewTarget("name", configMapName, "namespace", shootNamespace, "kind", "ConfigMap")},
		),
		Entry("should pass if the structured authentication config has anonymous access disabled",
			func() {
				authenticationConfigMap.Data = map[string]string{
					fileName: disabledAnonymousAuthenticationConfig,
				}

				Expect(fakeClient.Create(ctx, authenticationConfigMap)).To(Succeed())

				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						StructuredAuthentication: &gardencorev1beta1.StructuredAuthentication{
							ConfigMapName: configMapName,
						},
					},
				}
			},
			rule.CheckResult{Status: rule.Passed, Message: "Anonymous authentication is disabled for the kube-apiserver.", Target: rule.NewTarget("name", configMapName, "namespace", shootNamespace, "kind", "ConfigMap")},
		),
	)
})
