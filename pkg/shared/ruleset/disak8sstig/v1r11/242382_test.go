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

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ = Describe("#242382", func() {
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
		r := &v1r11.Rule242382{Client: fakeClient, Namespace: namespace}
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
		func(expectedModes []string, container corev1.Container, expectedCheckResults []rule.CheckResult, errorMatcher gomegatypes.GomegaMatcher) {
			kcmDeployment.Spec.Template.Spec.Containers = []corev1.Container{container}
			Expect(fakeClient.Create(ctx, kcmDeployment)).To(Succeed())

			r := &v1r11.Rule242382{
				Client:        fakeClient,
				Namespace:     namespace,
				ExpectedModes: expectedModes,
			}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should fail when authorization-mode is not set", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--flag1=value1", "--flag2=value2"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option authorization-mode has not been set.", Target: target}},
			BeNil()),
		Entry("should pass when authorization-mode is set to expected value Node,RBAC", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=Node,RBAC"}},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Option authorization-mode set to expected value.", Target: target}},
			BeNil()),
		Entry("should fail when authorization-mode is set to not expected value RBAC,Node", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=RBAC,Node"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option authorization-mode set to not expected value.", Target: target}},
			BeNil()),
		Entry("should fail when authorization-mode is set to not allowed value AlwaysAllow", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=AlwaysAllow"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option authorization-mode set to not allowed value.", Target: target}},
			BeNil()),
		Entry("should fail when authorization-mode is set to not allowed value RBAC,Node,AlwaysAllow", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=RBAC,Node,AlwaysAllow"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option authorization-mode set to not allowed value.", Target: target}},
			BeNil()),
		Entry("should fail when authorization-mode is set to not expected value Node", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=Node"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option authorization-mode set to not expected value.", Target: target}},
			BeNil()),
		Entry("should fail when authorization-mode is set to not expected value RBAC,Node,other", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=RBAC,Node,other"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option authorization-mode set to not expected value.", Target: target}},
			BeNil()),
		Entry("should return correct checkResults when expectedModes are set", []string{"RBAC", "Webhook"},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=RBAC,Webhook"}},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Option authorization-mode set to expected value.", Target: target}},
			BeNil()),
		Entry("should warn when authorization-mode is set more than once", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=RBAC,Node"}, Args: []string{"--authorization-mode=Node,RBAC"}},
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option authorization-mode has been set more than once in container command.", Target: target}},
			BeNil()),
		Entry("should error when deployment does not have container 'kube-apiserver'", []string{},
			corev1.Container{Name: "not-kube-apiserver", Command: []string{"--authorization-mode=RBAC,Node"}},
			[]rule.CheckResult{{Status: rule.Errored, Message: "deployment: kube-apiserver does not contain container: kube-apiserver", Target: target}},
			BeNil()),
	)
})
