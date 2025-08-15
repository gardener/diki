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

	intkubeutils "github.com/gardener/diki/pkg/internal/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#254800", func() {
	const (
		admissionConfig = `apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: baseline
      audit: baseline
      warn: baseline`
		admissionConfigWithPath = `apiVersion: apiserver.k8s.io/v1alpha1
kind: AdmissionConfiguration
plugins:
- configuration: null
  name: PodSecurity
  path: /foo/bar/podsecurity.yaml`
		admissionConfigWithoutPlugins = `apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration`
		podSecurityPrivileged = `apiVersion: pod-security.admission.config.k8s.io/v1alpha1
defaults:
  audit: privileged
  enforce: privileged
  warn: privileged
kind: PodSecurityConfiguration`
		podSecurityBaseline = `apiVersion: pod-security.admission.config.k8s.io/v1beta1
defaults:
  audit: baseline
  enforce: baseline
  warn: baseline
kind: PodSecurityConfiguration`
		podSecurityRestricted = `apiVersion: pod-security.admission.config.k8s.io/v1
defaults:
  audit: restricted
  enforce: restricted
  warn: restricted
kind: PodSecurityConfiguration`
	)

	var (
		fakeClient        client.Client
		ctx               = context.TODO()
		namespace         = "foo"
		fileName          = "fileName.yaml"
		configMapName     = "kube-apiserver-admission-config"
		configMapData     = "configMapData"
		deployment        *appsv1.Deployment
		configMap         *corev1.ConfigMap
		deployTarget      = rule.NewTarget("name", "kube-apiserver", "namespace", namespace, "kind", "Deployment")
		podSecurityTarget = rule.NewTarget("kind", "PodSecurityConfiguration")
		genericTarget     = rule.NewTarget()
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		deployment = &appsv1.Deployment{
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
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "admission-config-cm",
										MountPath: "/foo/bar",
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "admission-config-cm",
								VolumeSource: corev1.VolumeSource{
									ConfigMap: &corev1.ConfigMapVolumeSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: configMapName,
										},
									},
								},
							},
						},
					},
				},
			},
		}
		configMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      configMapName,
				Namespace: namespace,
			},
			Data: map[string]string{
				fileName: configMapData,
			},
		}
	})

	It("should error when kube-apiserver is not found", func() {
		r := &rules.Rule254800{Client: fakeClient, Namespace: namespace}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			{
				Status:  rule.Errored,
				Message: "deployments.apps \"kube-apiserver\" not found",
				Target:  deployTarget,
			},
		}))
	})

	DescribeTable("Run cases",
		func(command []string, configMapData map[string]string, options *rules.Options254800, expectedCheckResults []rule.CheckResult, errorMatcher gomegatypes.GomegaMatcher) {
			deployment.Spec.Template.Spec.Containers[0].Command = command
			Expect(fakeClient.Create(ctx, deployment)).To(Succeed())

			configMap.Data = configMapData
			Expect(fakeClient.Create(ctx, configMap)).To(Succeed())

			r := &rules.Rule254800{Client: fakeClient, Namespace: namespace, Options: options}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should warn when admission-control-config-file is not set",
			[]string{"--flag1=value1", "--flag2=value2"},
			map[string]string{}, nil,
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option admission-control-config-file has not been set.", Target: deployTarget}},
			BeNil()),
		Entry("should warn when admission-control-config-file is set more than once",
			[]string{"--admission-control-config-file=/foo/bar/fileName.yaml", "--admission-control-config-file=/foo/fileName.yaml"},
			map[string]string{}, nil,
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option admission-control-config-file has been set more than once in container command.", Target: deployTarget}},
			BeNil()),
		Entry("should return passed when options are defaulted to baseline",
			[]string{"--admission-control-config-file=/foo/bar/fileName.yaml"},
			map[string]string{fileName: admissionConfig}, nil,
			[]rule.CheckResult{{Status: rule.Passed, Message: "PodSecurity is properly configured", Target: podSecurityTarget}},
			BeNil()),
		Entry("should return passed when options are set to baseline",
			[]string{"--admission-control-config-file=/foo/bar/fileName.yaml"},
			map[string]string{fileName: admissionConfig}, &rules.Options254800{MinPodSecurityStandardsProfile: "baseline"},
			[]rule.CheckResult{{Status: rule.Passed, Message: "PodSecurity is properly configured", Target: podSecurityTarget}},
			BeNil()),
		Entry("should return failed when PodSecurity is not configured",
			[]string{"--admission-control-config-file=/foo/bar/fileName.yaml"},
			map[string]string{fileName: admissionConfigWithoutPlugins}, &rules.Options254800{MinPodSecurityStandardsProfile: "baseline"},
			[]rule.CheckResult{{Status: rule.Failed, Message: "PodSecurity is not configured", Target: genericTarget}},
			BeNil()),
		Entry("should return correct checkResults when config missing and path present",
			[]string{"--admission-control-config-file=/foo/bar/fileName.yaml"},
			map[string]string{fileName: admissionConfigWithPath, "podsecurity.yaml": podSecurityBaseline}, &rules.Options254800{MinPodSecurityStandardsProfile: "baseline"},
			[]rule.CheckResult{{Status: rule.Passed, Message: "PodSecurity is properly configured", Target: podSecurityTarget}},
			BeNil()),
		Entry("should return failed checkResults when using baseline and expected is restricted",
			[]string{"--admission-control-config-file=/foo/bar/fileName.yaml"},
			map[string]string{fileName: admissionConfigWithPath, "podsecurity.yaml": podSecurityBaseline}, &rules.Options254800{MinPodSecurityStandardsProfile: "restricted"},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Enforce mode profile is less restrictive than the minimum Pod Security Standards profile allowed: restricted", Target: podSecurityTarget},
				{Status: rule.Failed, Message: "Audit mode profile is less restrictive than the minimum Pod Security Standards profile allowed: restricted", Target: podSecurityTarget},
				{Status: rule.Failed, Message: "Warn mode profile is less restrictive than the minimum Pod Security Standards profile allowed: restricted", Target: podSecurityTarget}},
			BeNil()),
		Entry("should return passed checkResults when using privileged and expected is privileged",
			[]string{"--admission-control-config-file=/foo/bar/fileName.yaml"},
			map[string]string{fileName: admissionConfigWithPath, "podsecurity.yaml": podSecurityPrivileged}, &rules.Options254800{MinPodSecurityStandardsProfile: "privileged"},
			[]rule.CheckResult{{Status: rule.Passed, Message: "PodSecurity is properly configured", Target: podSecurityTarget}},
			BeNil()),
	)

	Describe("#Validate", func() {
		It("should not error when options are correct", func() {
			options := &rules.Options254800{
				MinPodSecurityStandardsProfile: "baseline",
			}

			result := options.Validate(field.NewPath("foo"))

			Expect(result).To(BeNil())
		})
		It("should return correct error when option is misconfigured", func() {
			options := &rules.Options254800{
				MinPodSecurityStandardsProfile: "foo",
			}

			result := options.Validate(field.NewPath("foo"))

			Expect(result).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":     Equal(field.ErrorTypeInvalid),
				"Field":    Equal("foo.minPodSecurityStandardsProfile"),
				"BadValue": Equal(intkubeutils.PodSecurityStandardProfile("foo")),
				"Detail":   Equal("must be one of 'restricted', 'baseline' or 'privileged'"),
			}))))
		})
	})
})
