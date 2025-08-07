// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	gomegatypes "github.com/onsi/gomega/types"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#242390", func() {

	const (
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
		invalidAnoymousAuthenticationConfig = "foo"
	)

	var (
		fakeClient client.Client
		ctx        = context.TODO()
		namespace  = "foo"

		ksDeployment *appsv1.Deployment
		target       = rule.NewTarget("name", "kube-apiserver", "namespace", namespace, "kind", "Deployment")
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		ksDeployment = &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-apiserver",
				Namespace: namespace,
			},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:    "kube-apiserver",
								Command: []string{},
								Args:    []string{},
							},
						},
					},
				},
			},
		}
	})
	It("should error when kube-apiserver is not found", func() {
		r := &rules.Rule242390{Client: fakeClient, Namespace: namespace}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			{
				Status:  rule.Errored,
				Message: "deployments.apps \"kube-apiserver\" not found",
				Target:  target,
			},
		},
		))
	})

	DescribeTable("Run cases for anonymous-authentication flag",
		func(container corev1.Container, expectedCheckResults []rule.CheckResult, errorMatcher gomegatypes.GomegaMatcher) {
			ksDeployment.Spec.Template.Spec.Containers = []corev1.Container{container}
			Expect(fakeClient.Create(ctx, ksDeployment)).To(Succeed())

			r := &rules.Rule242390{Client: fakeClient, Namespace: namespace}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},
		Entry("should pass when anonymous-auth is set to accepted value false",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--anonymous-auth=false"}},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Option anonymous-auth set to accepted value.", Target: target}},
			BeNil()),
		Entry("should warn when anonymous-auth is set more than once",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--anonymous-auth=false"}, Args: []string{"--anonymous-auth=true"}},
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option anonymous-auth has been set more than once in container command.", Target: target}},
			BeNil()),
		Entry("should error when deployment does not have container 'kube-apiserver'",
			corev1.Container{Name: "not-kube-apiserver", Command: []string{"--anonymous-auth=false"}},
			[]rule.CheckResult{{Status: rule.Errored, Message: "deployment: kube-apiserver does not contain container: kube-apiserver", Target: target}},
			BeNil()),
		Entry("should fail when anonymous-auth is set to not accepted value true",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--anonymous-auth=true"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option anonymous-auth set to not accepted value.", Target: target}},
			BeNil()),
	)

	DescribeTable("Run cases for authentication-config flag",
		func(container corev1.Container, modifyKAPIServer func(), options *rules.Options242390, expectedCheckResults []rule.CheckResult, errorMatcher gomegatypes.GomegaMatcher) {
			ksDeployment.Spec.Template.Spec.Containers = []corev1.Container{container}
			modifyKAPIServer()
			Expect(fakeClient.Create(ctx, ksDeployment)).To(Succeed())

			r := &rules.Rule242390{Client: fakeClient, Namespace: namespace, Options: options}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},
		Entry("should warn if neither the anonymous-auth nor authentication-config options are set",
			corev1.Container{Name: "kube-apiserver", Command: []string{}},
			func() {},
			nil,
			[]rule.CheckResult{{Status: rule.Warning, Message: "Neither options anonymous-auth nor authentication-config have been set.", Target: target}},
			BeNil()),
		Entry("should warn if the authentication-config flag is set more than once",
			corev1.Container{
				Name:    "kube-apiserver",
				Command: []string{"--authentication-config=/etc/foo/bar", "--authentication-config=/etc/foo/baz"},
			},
			func() {},
			nil,
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option authentication-config has been set more than once in container command.", Target: target}},
			BeNil()),
		Entry("should error if the volume cannot be retrieved from the mount",
			corev1.Container{
				Name:    "kube-apiserver",
				Command: []string{"--authentication-config=/etc/foo/bar"},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "authentication-config",
						MountPath: "/etc/foo/bar",
					},
				},
			},
			func() {},
			nil,
			[]rule.CheckResult{{Status: rule.Errored, Message: "deployment does not contain volume with name: authentication-config", Target: target}},
			BeNil()),
		Entry("should error if the configMap cannot be parsed",
			corev1.Container{
				Name:    "kube-apiserver",
				Command: []string{"--authentication-config=/etc/foo/bar"},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "authentication-config",
						MountPath: "/etc/foo/bar",
					},
				},
			},
			func() {
				ksDeployment.Spec.Template.Spec.Volumes = []corev1.Volume{{
					Name: "authentication-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "authentication-config",
							},
						},
					},
				}}

				configMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "authentication-config",
						Namespace: namespace,
					},
					Data: map[string]string{
						"/etc/foo/bar": invalidAnoymousAuthenticationConfig,
					},
				}
				Expect(fakeClient.Create(ctx, configMap)).To(Succeed())
			},
			nil,
			[]rule.CheckResult{{Status: rule.Errored, Message: "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `foo` into v1beta1.AuthenticationConfiguration", Target: target}},
			BeNil()),
		Entry("should fail if the authentication configuration has anonymous authentication enabled unconditionally.",
			corev1.Container{
				Name:    "kube-apiserver",
				Command: []string{"--authentication-config=/etc/foo/bar"},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "authentication-config",
						MountPath: "/etc/foo/bar",
					},
				},
			},
			func() {
				ksDeployment.Spec.Template.Spec.Volumes = []corev1.Volume{{
					Name: "authentication-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "authentication-config",
							},
						},
					},
				}}

				configMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "authentication-config",
						Namespace: namespace,
					},
					Data: map[string]string{
						"/etc/foo/bar": enabledAnonymousAuthenticationConfigWithConditions,
					},
				}
				Expect(fakeClient.Create(ctx, configMap)).To(Succeed())
			},
			nil,
			[]rule.CheckResult{{Status: rule.Failed, Message: "The authentication configuration has anonymous authentication enabled.", Target: target}},
			BeNil()),
		Entry("should fail if the authentication configuration has anonymous authentication enabled with conditions.",
			corev1.Container{
				Name:    "kube-apiserver",
				Command: []string{"--authentication-config=/etc/foo/bar"},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "authentication-config",
						MountPath: "/etc/foo/bar",
					},
				},
			},
			func() {
				ksDeployment.Spec.Template.Spec.Volumes = []corev1.Volume{{
					Name: "authentication-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "authentication-config",
							},
						},
					},
				}}

				configMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "authentication-config",
						Namespace: namespace,
					},
					Data: map[string]string{
						"/etc/foo/bar": enabledAnonymousAuthenticationConfigWithoutConditions,
					},
				}
				Expect(fakeClient.Create(ctx, configMap)).To(Succeed())
			},
			nil,
			[]rule.CheckResult{{Status: rule.Failed, Message: "The authentication configuration has anonymous authentication enabled.", Target: target}},
			BeNil()),
		Entry("should pass if the authentication configuration has anonymous authentication disabled.",
			corev1.Container{
				Name:    "kube-apiserver",
				Command: []string{"--authentication-config=/etc/foo/bar"},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "authentication-config",
						MountPath: "/etc/foo/bar",
					},
				},
			},
			func() {
				ksDeployment.Spec.Template.Spec.Volumes = []corev1.Volume{{
					Name: "authentication-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "authentication-config",
							},
						},
					},
				}}

				configMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "authentication-config",
						Namespace: namespace,
					},
					Data: map[string]string{
						"/etc/foo/bar": disabledAnonymousAuthenticationConfig,
					},
				}
				Expect(fakeClient.Create(ctx, configMap)).To(Succeed())
			},
			nil,
			[]rule.CheckResult{{Status: rule.Passed, Message: "The authentication configuration has anonymous authentication disabled.", Target: target}},
			BeNil()),
		Entry("should be accepted if the enabled condition endpoints are configured in the rule options.",
			corev1.Container{
				Name:    "kube-apiserver",
				Command: []string{"--authentication-config=/etc/foo/bar"},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "authentication-config",
						MountPath: "/etc/foo/bar",
					},
				},
			},
			func() {
				ksDeployment.Spec.Template.Spec.Volumes = []corev1.Volume{{
					Name: "authentication-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "authentication-config",
							},
						},
					},
				}}

				configMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "authentication-config",
						Namespace: namespace,
					},
					Data: map[string]string{
						"/etc/foo/bar": enabledAnonymousAuthenticationConfigWithConditions,
					},
				}
				Expect(fakeClient.Create(ctx, configMap)).To(Succeed())
			},
			&rules.Options242390{
				AcceptedEndpoints: []rules.AcceptedEndpoint{
					{
						Path: "/healthz",
					},
					{
						Path: "/readyz",
					},
					{
						Path: "/livez",
					},
					{
						Path: "/fooz",
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Accepted, Message: "Anonymous authentication is accepted for the specified endpoints of the kube-apiserver.", Target: target.With("details", "endpoint: /healthz")},
				{Status: rule.Accepted, Message: "Anonymous authentication is accepted for the specified endpoints of the kube-apiserver.", Target: target.With("details", "endpoint: /livez")},
				{Status: rule.Accepted, Message: "Anonymous authentication is accepted for the specified endpoints of the kube-apiserver.", Target: target.With("details", "endpoint: /readyz")},
			},
			BeNil()),
		Entry("should fail if an enabled condition endpoint is not configured in the rule options.",
			corev1.Container{
				Name:    "kube-apiserver",
				Command: []string{"--authentication-config=/etc/foo/bar"},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "authentication-config",
						MountPath: "/etc/foo/bar",
					},
				},
			},
			func() {
				ksDeployment.Spec.Template.Spec.Volumes = []corev1.Volume{{
					Name: "authentication-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "authentication-config",
							},
						},
					},
				}}

				configMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "authentication-config",
						Namespace: namespace,
					},
					Data: map[string]string{
						"/etc/foo/bar": enabledAnonymousAuthenticationConfigWithConditions,
					},
				}
				Expect(fakeClient.Create(ctx, configMap)).To(Succeed())
			},
			&rules.Options242390{
				AcceptedEndpoints: []rules.AcceptedEndpoint{
					{
						Path: "/healthz",
					},
					{
						Path: "/barz",
					},
					{
						Path: "/fooz",
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Accepted, Message: "Anonymous authentication is accepted for the specified endpoints of the kube-apiserver.", Target: target.With("details", "endpoint: /healthz")},
				{Status: rule.Failed, Message: "Anonymous authentication is enabled for specific endpoints of the kube-apiserver.", Target: target.With("details", "endpoint: /livez")},
				{Status: rule.Failed, Message: "Anonymous authentication is enabled for specific endpoints of the kube-apiserver.", Target: target.With("details", "endpoint: /readyz")},
			},
			BeNil()),
		Entry("should fail if anonymous authentication is enabled unconditionally and options are configured",
			corev1.Container{
				Name:    "kube-apiserver",
				Command: []string{"--authentication-config=/etc/foo/bar"},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "authentication-config",
						MountPath: "/etc/foo/bar",
					},
				},
			},
			func() {
				ksDeployment.Spec.Template.Spec.Volumes = []corev1.Volume{{
					Name: "authentication-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "authentication-config",
							},
						},
					},
				}}

				configMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "authentication-config",
						Namespace: namespace,
					},
					Data: map[string]string{
						"/etc/foo/bar": enabledAnonymousAuthenticationConfigWithoutConditions,
					},
				}
				Expect(fakeClient.Create(ctx, configMap)).To(Succeed())
			},
			&rules.Options242390{
				AcceptedEndpoints: []rules.AcceptedEndpoint{
					{
						Path: "/healthz",
					},
					{
						Path: "/barz",
					},
					{
						Path: "/fooz",
					},
				},
			},
			[]rule.CheckResult{{Status: rule.Failed, Message: "The authentication configuration has anonymous authentication enabled.", Target: target}},
			BeNil()),
	)

	Describe("#ValidateOptions242390", func() {
		It("should deny empty accepted endpoints list", func() {
			options := rules.Options242390{}

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
			options := rules.Options242390{
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
