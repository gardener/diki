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

	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242377", func() {
	var (
		fakeClient client.Client
		ctx        = context.TODO()
		namespace  = "foo"

		ksDeployment *appsv1.Deployment
		target       = rule.NewTarget("cluster", "seed", "name", "kube-scheduler", "namespace", namespace, "kind", "Deployment")
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		ksDeployment = &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-scheduler",
				Namespace: namespace,
			},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:    "kube-scheduler",
								Command: []string{},
								Args:    []string{},
							},
						},
					},
				},
			},
		}
	})

	It("should error when kube-scheduler is not found", func() {
		r := &rules.Rule242377{Client: fakeClient, Namespace: namespace}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			{
				Status:  rule.Errored,
				Message: "deployments.apps \"kube-scheduler\" not found",
				Target:  target,
			},
		},
		))
	})

	DescribeTable("Run cases",
		func(container corev1.Container, expectedCheckResults []rule.CheckResult, errorMatcher gomegatypes.GomegaMatcher) {
			ksDeployment.Spec.Template.Spec.Containers = []corev1.Container{container}
			Expect(fakeClient.Create(ctx, ksDeployment)).To(Succeed())

			r := &rules.Rule242377{Client: fakeClient, Namespace: namespace}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should pass when tls-min-version is not set",
			corev1.Container{Name: "kube-scheduler", Command: []string{"--flag1=value1", "--flag2=value2"}},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Option tls-min-version has not been set.", Target: target}},
			BeNil()),
		Entry("should fail when tls-min-version is set to not allowed value VersionTLS10",
			corev1.Container{Name: "kube-scheduler", Command: []string{"--tls-min-version=VersionTLS10"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option tls-min-version set to not allowed value.", Target: target}},
			BeNil()),
		Entry("should fail when tls-min-version is set to not allowed value VersionTLS11",
			corev1.Container{Name: "kube-scheduler", Command: []string{"--tls-min-version=VersionTLS11"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option tls-min-version set to not allowed value.", Target: target}},
			BeNil()),
		Entry("should pass when tls-min-version is set to allowed value",
			corev1.Container{Name: "kube-scheduler", Command: []string{"--tls-min-version=VersionTLS12"}},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Option tls-min-version set to allowed value.", Target: target}},
			BeNil()),
		Entry("should warn when tls-min-version is set more than once",
			corev1.Container{Name: "kube-scheduler", Command: []string{"--tls-min-version=VersionTLS11"}, Args: []string{"--tls-min-version=VersionTLS12"}},
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option tls-min-version has been set more than once in container command.", Target: target}},
			BeNil()),
		Entry("should error when deployment does not have container 'kube-scheduler'",
			corev1.Container{Name: "not-kube-scheduler", Command: []string{"--tls-min-version=VersionTLS12"}},
			[]rule.CheckResult{{Status: rule.Errored, Message: "deployment: kube-scheduler does not contain container: kube-scheduler", Target: target}},
			BeNil()),
	)
})
