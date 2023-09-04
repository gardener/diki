// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r8"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242417", func() {
	var (
		fakeClient client.Client
		pod        *corev1.Pod
		ctx        = context.TODO()
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shoot-pod",
				Namespace: "namespace",
				Labels:    map[string]string{},
			},
		}
	})

	It("should return passed checkResult when no user pods are present in system namespaces", func() {
		pod1 := pod.DeepCopy()
		pod1.Name = "pod1"
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := pod.DeepCopy()
		pod2.Name = "bar"
		pod2.Namespace = "kube-system"
		pod2.Labels["resources.gardener.cloud/managed-by"] = "gardener"
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		pod3 := pod.DeepCopy()
		pod3.Name = "bar"
		pod3.Namespace = "kube-public"
		pod3.Labels["resources.gardener.cloud/managed-by"] = "gardener"
		Expect(fakeClient.Create(ctx, pod3)).To(Succeed())

		pod4 := pod.DeepCopy()
		pod4.Name = "bar"
		pod4.Namespace = "kube-node-lease"
		pod4.Labels["compliance.gardener.cloud/role"] = "diki-privileged-pod"
		Expect(fakeClient.Create(ctx, pod4)).To(Succeed())

		r := &v1r8.Rule242417{Logger: testLogger, Client: fakeClient}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("Found no user pods in system namespaces.", gardener.NewTarget("cluster", "shoot")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return failed checkResult when user pods are present in system namespaces", func() {
		pod1 := pod.DeepCopy()
		pod1.Name = "foo"
		pod1.Namespace = "kube-system"
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := pod.DeepCopy()
		pod2.Name = "bar"
		pod2.Namespace = "kube-public"
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		pod3 := pod.DeepCopy()
		pod3.Name = "foobar"
		pod3.Namespace = "kube-node-lease"
		Expect(fakeClient.Create(ctx, pod3)).To(Succeed())

		r := &v1r8.Rule242417{Logger: testLogger, Client: fakeClient}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Found user pods in system namespaces.", gardener.NewTarget("cluster", "shoot", "name", pod1.Name, "namespace", pod1.Namespace, "kind", "pod")),
			rule.FailedCheckResult("Found user pods in system namespaces.", gardener.NewTarget("cluster", "shoot", "name", pod2.Name, "namespace", pod2.Namespace, "kind", "pod")),
			rule.FailedCheckResult("Found user pods in system namespaces.", gardener.NewTarget("cluster", "shoot", "name", pod3.Name, "namespace", pod3.Namespace, "kind", "pod")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
})
