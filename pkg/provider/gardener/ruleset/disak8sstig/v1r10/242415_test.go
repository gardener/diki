// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r10"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242415", func() {
	var (
		fakeSeedClient  client.Client
		fakeShootClient client.Client
		seedPod         *corev1.Pod
		shootPod        *corev1.Pod
		ctx             = context.TODO()
		namespace       = "foo"
	)

	BeforeEach(func() {
		fakeSeedClient = fakeclient.NewClientBuilder().Build()
		fakeShootClient = fakeclient.NewClientBuilder().Build()
		seedPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "seed-pod",
				Namespace: namespace,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "test",
						Env:  []corev1.EnvVar{},
					},
				},
			},
		}
		shootPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shoot-pod",
				Namespace: namespace,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "test",
						Env:  []corev1.EnvVar{},
					},
				},
			},
		}
	})

	It("should return correct results when all pods pass", func() {
		r := &v1r10.Rule242415{Logger: testLogger, ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace}
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not use environment to inject secret.",
				Target:  gardener.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "foo", "kind", "pod"),
			},
			{
				Status:  rule.Passed,
				Message: "Pod does not use environment to inject secret.",
				Target:  gardener.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "foo", "kind", "pod"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when a pod fails", func() {
		r := &v1r10.Rule242415{Logger: testLogger, ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace}
		shootPod.Spec.Containers[0].Env = []corev1.EnvVar{
			{
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						Key: "secret_test",
					},
				},
			},
		}
		shootPod.Spec.Containers[0].Ports = []corev1.ContainerPort{
			{
				Name: "port_test",
			},
		}
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not use environment to inject secret.",
				Target:  gardener.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "foo", "kind", "pod"),
			},
			{
				Status:  rule.Failed,
				Message: "Pod uses environment to inject secret.",
				Target:  gardener.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "foo", "kind", "pod", "details", "containerName: test, keyRef: secret_test"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
})
