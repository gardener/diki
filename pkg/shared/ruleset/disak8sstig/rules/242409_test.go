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

var _ = Describe("#242409", func() {
	var (
		fakeClient client.Client
		ctx        = context.TODO()
		namespace  = "foo"

		kcmDeployment *appsv1.Deployment
		target        = rule.NewTarget("name", "kube-controller-manager", "namespace", namespace, "kind", "Deployment")
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		kcmDeployment = &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-controller-manager",
				Namespace: namespace,
			},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:    "kube-controller-manager",
								Command: []string{},
								Args:    []string{},
							},
						},
					},
				},
			},
		}
	})

	It("should error when kube-controller-manager is not found", func() {
		r := &rules.Rule242409{Client: fakeClient, Namespace: namespace}
		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			{
				Status:  rule.Errored,
				Message: "deployments.apps \"kube-controller-manager\" not found",
				Target:  target,
			},
		},
		))
	})

	DescribeTable("Run cases",
		func(container corev1.Container, expectedCheckResults []rule.CheckResult, errorMatcher gomegatypes.GomegaMatcher) {
			kcmDeployment.Spec.Template.Spec.Containers = []corev1.Container{container}
			Expect(fakeClient.Create(ctx, kcmDeployment)).To(Succeed())

			r := &rules.Rule242409{Client: fakeClient, Namespace: namespace}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should warn when profiling is not set",
			corev1.Container{Name: "kube-controller-manager", Command: []string{"--flag1=value1", "--flag2=value2"}},
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option profiling has not been set.", Target: target}},
			BeNil()),
		Entry("should pass when profiling is set to allowed value false",
			corev1.Container{Name: "kube-controller-manager", Command: []string{"--profiling=false"}},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Option profiling set to allowed value.", Target: target}},
			BeNil()),
		Entry("should fail when profiling is set to not allowed value true",
			corev1.Container{Name: "kube-controller-manager", Command: []string{"--profiling=true"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option profiling set to not allowed value.", Target: target}},
			BeNil()),
		Entry("should warn when profiling is set to neither 'true' nor 'false'",
			corev1.Container{Name: "kube-controller-manager", Command: []string{"--profiling=f"}},
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option profiling set to neither 'true' nor 'false'.", Target: target}},
			BeNil()),
		Entry("should warn when profiling is set more than once",
			corev1.Container{Name: "kube-controller-manager", Command: []string{"--profiling=true"}, Args: []string{"--profiling=false"}},
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option profiling has been set more than once in container command.", Target: target}},
			BeNil()),
		Entry("should error when deployment does not have container 'kube-controller-manager'",
			corev1.Container{Name: "not-kube-controller-manager", Command: []string{"--profiling=true"}},
			[]rule.CheckResult{{Status: rule.Errored, Message: "deployment: kube-controller-manager does not contain container: kube-controller-manager", Target: target}},
			BeNil()),
	)
})
