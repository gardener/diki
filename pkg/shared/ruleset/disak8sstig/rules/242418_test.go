// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#242418", func() {
	const requiredCiphers = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	var (
		fakeClient client.Client
		ctx        = context.TODO()
		namespace  = "foo"

		kcmDeployment *appsv1.Deployment
		target        = rule.NewTarget("name", "kube-apiserver", "namespace", namespace, "kind", "deployment")
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		kcmDeployment = &appsv1.Deployment{
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
		r := &rules.Rule242418{Client: fakeClient, Namespace: namespace}
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

	DescribeTable("Run cases",
		func(container corev1.Container, expectedCheckResults []rule.CheckResult, errorMatcher gomegatypes.GomegaMatcher) {
			kcmDeployment.Spec.Template.Spec.Containers = []corev1.Container{container}
			Expect(fakeClient.Create(ctx, kcmDeployment)).To(Succeed())

			r := &rules.Rule242418{Client: fakeClient, Namespace: namespace}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should warn when tls-cipher-suites is not set",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--flag1=value1", "--flag2=value2"}},
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option tls-cipher-suites has not been set.", Target: target}},
			BeNil()),
		Entry("should pass when tls-cipher-suites is set to allowed values",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--tls-cipher-suites=TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256," + requiredCiphers}},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Option tls-cipher-suites set to allowed values.", Target: target}},
			BeNil()),
		Entry("should fail when tls-cipher-suites does not contain all required ciphers",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option tls-cipher-suites set to not allowed values.", Target: target}},
			BeNil()),
		Entry("should fail when tls-cipher-suites contains hard-coded insecure ciphers",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA," + requiredCiphers}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option tls-cipher-suites set to not allowed values.", Target: target}},
			BeNil()),
		Entry("should fail when tls-cipher-suites contains insecure ciphers",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--tls-cipher-suites=TLS_RSA_WITH_RC4_128_SHA," + requiredCiphers}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option tls-cipher-suites set to not allowed values.", Target: target}},
			BeNil()),
		Entry("should warn when tls-cipher-suites is set more than once",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--tls-cipher-suites=foo,bar"}, Args: []string{"--tls-cipher-suites=foobar"}},
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option tls-cipher-suites has been set more than once in container command.", Target: target}},
			BeNil()),
		Entry("should error when deployment does not have container 'kube-apiserver'",
			corev1.Container{Name: "not-kube-apiserver", Command: []string{"--tls-cipher-suites=foo"}},
			[]rule.CheckResult{{Status: rule.Errored, Message: "deployment: kube-apiserver does not contain container: kube-apiserver", Target: target}},
			BeNil()),
	)
})
