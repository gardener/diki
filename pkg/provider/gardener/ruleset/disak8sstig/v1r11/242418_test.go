// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11_test

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

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242418", func() {
	var (
		fakeClient client.Client
		ctx        = context.TODO()
		namespace  = "foo"

		kcmDeployment *appsv1.Deployment
		target        = gardener.NewTarget("cluster", "seed", "name", "kube-apiserver", "namespace", namespace, "kind", "deployment")
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
		r := &v1r11.Rule242418{Logger: testLogger, Client: fakeClient, Namespace: namespace}
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

			r := &v1r11.Rule242418{Logger: testLogger, Client: fakeClient, Namespace: namespace}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should warn when tls-cipher-suites is not set",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--flag1=value1", "--flag2=value2"}},
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option tls-cipher-suites has not been set.", Target: target}},
			BeNil()),
		Entry("should pass when tls-cipher-suites is set to allowed values",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,foo,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,bar"}},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Option tls-cipher-suites set to allowed values.", Target: target}},
			BeNil()),
		Entry("should fail when tls-cipher-suites is set to not allowed values",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--tls-cipher-suites=foo,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,bar,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"}},
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
