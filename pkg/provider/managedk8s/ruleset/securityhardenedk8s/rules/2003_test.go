// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s/rules"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#2003", func() {

	var (
		fakeClient    client.Client
		plainPod      *corev1.Pod
		ctx           = context.TODO()
		namespaceName = "foo"
		namespace     *corev1.Namespace
		r             rules.Rule2003
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		namespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
		}
		plainPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
		}
	})

	DescribeTable("Run cases", func(updatePodConfig func(), ruleOptions *rules.Options2003, expectedCheckResults []rule.CheckResult) {
		Expect(fakeClient.Create(ctx, namespace)).To(Succeed())

		updatePodConfig()

		r = rules.Rule2003{Client: fakeClient, Options: ruleOptions}
		result, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(result).To(Equal(expectedCheckResults))
	},
		Entry("should pass when no pod volumes are found",
			func() {},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "No pod volumes found for evaluation.", Target: rule.NewTarget()},
			},
		),
	)
})
