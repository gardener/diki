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
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
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
		shoot                   *gardencorev1beta1.Shoot
		r                       rule.Rule
		ruleName                = "Shoot clusters must have anonymous authentication disabled for the Kubernetes API server."
		ruleID                  = "2000"
		severity                = rule.SeverityHigh
	)

	const (
		fileName                             = "config.yaml"
		configMapName                        = "authentication-config"
		invalidAnonymousAuthenticationConfig = "foo"

		disabledAnonymousAuthenticationConfig = `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
anonymous:
  enabled: false
`
		enabledAnonymousAuthenticationConfigWithConditions = `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
anonymous:
  enabled: true
  conditions:
  - path: /healthz
  - path: /livez
  - path: /readyz
`

		enabledAnonymousAuthenticationConfigWithoutConditions = `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
anonymous:
  enabled: true
`

		nilAnonymusAuthenticationConfig = `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
`
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
	})

	// TODO (georgibaltiev): remove any references to the EnableAnonymousAuthentication field after it's removal
	DescribeTable("Run cases", func(updateFn func(), options *rules.Options2000, expectedCheckResults []rule.CheckResult) {
		updateFn()

		r = &rules.Rule2000{
			Client:         fakeClient,
			ShootName:      shootName,
			ShootNamespace: shootNamespace,
			Options:        options,
		}

		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())
		res, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(Equal(rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: severity, CheckResults: expectedCheckResults}))
	},
		Entry("should error when the shoot is not found",
			func() { shoot.Name = "notFoo" },
			nil,
			[]rule.CheckResult{{Status: rule.Errored, Message: "shoots.core.gardener.cloud \"foo\" not found", Target: rule.NewTarget("kind", "Shoot", "name", "foo", "namespace", "bar")}},
		),
		Entry("should pass when kube-apiserver configuration is not set",
			func() {},
			nil,
			[]rule.CheckResult{{Status: rule.Passed, Message: "Anonymous authentication is not enabled for the kube-apiserver.", Target: rule.NewTarget()}},
		),
		Entry("should pass when the enabledAnoymousAuthentication flag is set to false",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						EnableAnonymousAuthentication: ptr.To(false),
					},
				}
			},
			nil,
			[]rule.CheckResult{{Status: rule.Passed, Message: "Anonymous authentication is disabled for the kube-apiserver.", Target: rule.NewTarget()}},
		),
		Entry("should fail when the enabledAnoymousAuthentication flag is set to true",
			func() {
				shoot.Spec.Kubernetes = gardencorev1beta1.Kubernetes{
					KubeAPIServer: &gardencorev1beta1.KubeAPIServerConfig{
						EnableAnonymousAuthentication: ptr.To(true),
					},
				}
			},
			nil,
			[]rule.CheckResult{{Status: rule.Failed, Message: "Anonymous authentication is enabled for the kube-apiserver.", Target: rule.NewTarget()}},
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
			nil,
			[]rule.CheckResult{{Status: rule.Passed, Message: "Anonymous authentication is not enabled for the kube-apiserver.", Target: rule.NewTarget()}},
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
			nil,
			[]rule.CheckResult{{Status: rule.Errored, Message: "configmaps \"authentication-config\" not found", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap")}},
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
			nil,
			[]rule.CheckResult{{Status: rule.Errored, Message: "configMap: authentication-config does not contain field: config.yaml in Data field", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap")}},
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
			nil,
			[]rule.CheckResult{{Status: rule.Errored, Message: "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `foo` into v1beta1.AuthenticationConfiguration", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap")}},
		),
		Entry("should pass if the structuredAuthentication configuration does not have anonymous authentication config set",
			func() {
				authenticationConfigMap.Data = map[string]string{
					fileName: nilAnonymusAuthenticationConfig,
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
			nil,
			[]rule.CheckResult{{Status: rule.Passed, Message: "Anonymous authentication is not enabled for the kube-apiserver.", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap")}},
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
			nil,
			[]rule.CheckResult{{Status: rule.Failed, Message: "Anonymous authentication is enabled for the kube-apiserver.", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap")}},
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
			nil,
			[]rule.CheckResult{{Status: rule.Failed, Message: "Anonymous authentication is enabled for the kube-apiserver.", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap")}},
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
			nil,
			[]rule.CheckResult{{Status: rule.Passed, Message: "Anonymous authentication is disabled for the kube-apiserver.", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap")}},
		),
		Entry("should be accepted if the structured authentication's conditions are present in the configured accepted endpoints", func() {
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
			&rules.Options2000{
				AcceptedEndpoints: []rules.AcceptedEndpoint{
					{
						Path: "/healthz",
					},
					{
						Path: "/livez",
					},
					{
						Path: "/readyz",
					},
					{
						Path: "/fooz",
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Accepted, Message: "Anonymous authentication is accepted for the specified endpoints of the kube-apiserver.", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap", "details", "endpoint: /healthz")},
				{Status: rule.Accepted, Message: "Anonymous authentication is accepted for the specified endpoints of the kube-apiserver.", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap", "details", "endpoint: /livez")},
				{Status: rule.Accepted, Message: "Anonymous authentication is accepted for the specified endpoints of the kube-apiserver.", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap", "details", "endpoint: /readyz")},
			},
		),
		Entry("should fail if the structured authentication's enabled conditions contain an endpoint that is not present in the rule options", func() {
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
			&rules.Options2000{
				AcceptedEndpoints: []rules.AcceptedEndpoint{
					{
						Path: "/livez",
					},
					{
						Path: "/fooz",
					},
					{
						Path: "/barzmak",
					},
					{
						Path: "/bazz",
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Anonymous authentication is enabled for specific endpoints of the kube-apiserver.", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap", "details", "endpoint: /healthz")},
				{Status: rule.Accepted, Message: "Anonymous authentication is accepted for the specified endpoints of the kube-apiserver.", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap", "details", "endpoint: /livez")},
				{Status: rule.Failed, Message: "Anonymous authentication is enabled for specific endpoints of the kube-apiserver.", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap", "details", "endpoint: /readyz")},
			},
		),
		Entry("should fail if the structured authentication's enabled without conditions and options are still present", func() {
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
			&rules.Options2000{
				AcceptedEndpoints: []rules.AcceptedEndpoint{
					{
						Path: "/livez",
					},
					{
						Path: "/healthz",
					},
				},
			},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Anonymous authentication is enabled for the kube-apiserver.", Target: rule.NewTarget("name", "authentication-config", "namespace", "bar", "kind", "ConfigMap")}},
		),
	)

	Describe("#ValidateOptions2000", func() {
		It("should deny empty accepted endpoints list", func() {
			options := rules.Options2000{}

			result := options.Validate()

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("acceptedEndpoints"),
					"Detail": Equal("must not be empty"),
				})),
			))
		})

		It("should correctly validate options", func() {
			options := rules.Options2000{
				AcceptedEndpoints: []rules.AcceptedEndpoint{
					{
						Path: "/healthz",
					},
					{
						Path: "",
					},
					{
						Path: "/barz",
					},
				},
			}

			result := options.Validate()

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("acceptedEndpoints[1].path"),
					"Detail": Equal("must not be empty"),
				})),
			))
		})
	})
})
