// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
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

	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242415", func() {
	var (
		fakeSeedClient     client.Client
		fakeShootClient    client.Client
		options            *v1r11.Options242415
		seedPod            *corev1.Pod
		shootPod           *corev1.Pod
		ctx                = context.TODO()
		seedNamespaceName  = "seed"
		shootNamespaceName = "shoot"
		seedNamespace      *corev1.Namespace
		shootNamespace     *corev1.Namespace
	)

	BeforeEach(func() {
		fakeSeedClient = fakeclient.NewClientBuilder().Build()
		fakeShootClient = fakeclient.NewClientBuilder().Build()

		shootNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: shootNamespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
		}

		seedNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: seedNamespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
		}

		seedPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "seed-pod",
				Namespace: seedNamespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
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
				Namespace: shootNamespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
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
		options = &v1r11.Options242415{}
	})

	It("should return correct results when all pods pass", func() {
		r := &v1r11.Rule242415{Logger: testLogger, ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: seedNamespaceName, Options: options}
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not use environment to inject secret.",
				Target:  rule.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "seed", "kind", "pod"),
			},
			{
				Status:  rule.Passed,
				Message: "Pod does not use environment to inject secret.",
				Target:  rule.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "shoot", "kind", "pod"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when a pod fails", func() {
		r := &v1r11.Rule242415{Logger: testLogger, ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: seedNamespaceName, Options: options}
		shootPod.Spec.Containers[0].Env = []corev1.EnvVar{
			{
				Name: "SECRET_TEST",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						Key: "secret_test",
					},
				},
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
				Target:  rule.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "seed", "kind", "pod"),
			},
			{
				Status:  rule.Failed,
				Message: "Pod uses environment to inject secret.",
				Target:  rule.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "shoot", "kind", "pod", "details", "containerName: test, variableName: SECRET_TEST, keyRef: secret_test"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when a pod has accepted environment variables", func() {
		options = &v1r11.Options242415{
			AcceptedPods: []v1r11.AcceptedPods242415{
				{
					PodMatchLabels:       map[string]string{"foo": "bar"},
					NamespaceMatchLabels: map[string]string{"foo": "bar"},
					EnvironmentVariables: []string{"SECRET_TEST"},
				},
			},
		}
		r := &v1r11.Rule242415{Logger: testLogger, ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: seedNamespaceName, Options: options}
		shootPod.Spec.Containers[0].Env = []corev1.EnvVar{
			{
				Name: "SECRET_TEST",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						Key: "secret_test",
					},
				},
			},
		}

		Expect(fakeSeedClient.Create(ctx, seedNamespace)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootNamespace)).To(Succeed())
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not use environment to inject secret.",
				Target:  rule.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "seed", "kind", "pod"),
			},
			{
				Status:  rule.Accepted,
				Message: "Pod accepted to use environment to inject secret.",
				Target:  rule.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "shoot", "kind", "pod", "details", "containerName: test, variableName: SECRET_TEST, keyRef: secret_test"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
})
