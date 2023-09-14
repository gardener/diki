// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10_test

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
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r10"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242388", func() {
	var (
		fakeClient client.Client
		ctx        = context.TODO()
		namespace  = "foo"

		ksDeployment *appsv1.Deployment
		target       = gardener.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-apiserver", "namespace", namespace)
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
		r := &v1r10.Rule242388{Logger: testLogger, Client: fakeClient, Namespace: namespace}

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
			ksDeployment.Spec.Template.Spec.Containers = []corev1.Container{container}
			Expect(fakeClient.Create(ctx, ksDeployment)).To(Succeed())

			r := &v1r10.Rule242388{Logger: testLogger, Client: fakeClient, Namespace: namespace}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should pass when insecure-bind-address is not set",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--flag1=value1", "--flag2=value2"}},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Option insecure-bind-address not set.", Target: target}},
			BeNil()),
		Entry("should fail when insecure-bind-address is set",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--insecure-bind-address=localhost"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option insecure-bind-address set.", Target: target}},
			BeNil()),
		Entry("should fail when insecure-bind-address is set more than once",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--insecure-bind-address=127.0.0.1"}, Args: []string{"--insecure-bind-address=255.255.255.255"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option insecure-bind-address set.", Target: target}},
			BeNil()),
		Entry("should error when deployment does not have container 'kube-apiserver'",
			corev1.Container{Name: "not-kube-apiserver", Command: []string{"--insecure-bind-address=255.255.255.255"}},
			[]rule.CheckResult{{Status: rule.Errored, Message: "deployment: kube-apiserver does not contain container: kube-apiserver", Target: target}},
			BeNil()),
	)
})
