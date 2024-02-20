// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ = Describe("#242395", func() {
	var (
		fakeClient client.Client
		pod        *corev1.Pod
		ctx        = context.TODO()
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod",
				Namespace: "namespace",
				Labels:    map[string]string{},
			},
		}
	})

	It("should return passed checkResult when dashboard is not installed", func() {
		pod1 := pod.DeepCopy()
		pod1.Name = "pod1"
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := pod.DeepCopy()
		pod2.Name = "pod2"
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		r := &v1r11.Rule242395{Client: fakeClient}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("Kubernetes dashboard not installed", rule.NewTarget()),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return failed checkResult when dashboard is not installed", func() {
		pod1 := pod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Labels["k8s-app"] = "kubernetes-dashboard"
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := pod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Labels["k8s-app"] = "kubernetes-dashboard"
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		r := &v1r11.Rule242395{Client: fakeClient}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Kubernetes dashboard installed", rule.NewTarget("name", pod1.Name, "namespace", pod1.Namespace, "kind", "pod")),
			rule.FailedCheckResult("Kubernetes dashboard installed", rule.NewTarget("name", pod2.Name, "namespace", pod2.Namespace, "kind", "pod")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
})
