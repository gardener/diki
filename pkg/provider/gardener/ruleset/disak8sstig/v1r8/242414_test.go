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
	dikirule "github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242414", func() {
	var (
		fakeSeedClient  client.Client
		fakeShootClient client.Client
		options         v1r8.Options242414
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
						Ports: []corev1.ContainerPort{
							{
								HostPort: 8888,
							},
						},
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
						Ports: []corev1.ContainerPort{
							{
								HostPort: 8888,
							},
						},
					},
				},
			},
		}
	})

	It("should return correct results when all pods pass", func() {
		rule := &v1r8.Rule242414{Logger: testLogger, ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace, Options: &options}
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := rule.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []dikirule.CheckResult{
			{
				Status:  dikirule.Passed,
				Message: "Container does not use hostPort < 1024.",
				Target:  gardener.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "foo", "kind", "pod"),
			},
			{
				Status:  dikirule.Passed,
				Message: "Container does not use hostPort < 1024.",
				Target:  gardener.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "foo", "kind", "pod"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when a pod fails", func() {
		rule := &v1r8.Rule242414{Logger: testLogger, ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace, Options: &options}
		shootPod.Spec.Containers[0].Ports[0].HostPort = 1011
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := rule.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []dikirule.CheckResult{
			{
				Status:  dikirule.Passed,
				Message: "Container does not use hostPort < 1024.",
				Target:  gardener.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "foo", "kind", "pod"),
			},
			{
				Status:  dikirule.Failed,
				Message: "Container may not use hostPort < 1024.",
				Target:  gardener.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "foo", "kind", "pod", "details", "containerName: test, port: 1011"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when options are present", func() {
		options = v1r8.Options242414{
			AcceptedPods: []struct {
				PodNamePrefix       string
				NamespaceNamePrefix string
				Justification       string
				Ports               []int32
			}{
				{
					PodNamePrefix:       "foo",
					NamespaceNamePrefix: "namespace",
					Ports:               []int32{58},
				},
				{
					PodNamePrefix:       "node-local-dns-",
					NamespaceNamePrefix: "namespace",
					Justification:       "foo justify",
					Ports:               []int32{53},
				},
			},
		}

		rule := &v1r8.Rule242414{Logger: testLogger, ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace, Options: &options}

		nodeLocalPod := shootPod.DeepCopy()
		nodeLocalPod.Name = "node-local-dns-123!"
		nodeLocalPod.Namespace = "namespace-test"
		nodeLocalPod.Spec.Containers[0].Ports[0].HostPort = 53

		fooPod := shootPod.DeepCopy()
		fooPod.Name = "foo"
		fooPod.Namespace = "namespace"
		fooPod.Spec.Containers[0].Ports[0].HostPort = 58

		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, nodeLocalPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, fooPod)).To(Succeed())

		ruleResult, err := rule.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []dikirule.CheckResult{
			{
				Status:  dikirule.Passed,
				Message: "Container does not use hostPort < 1024.",
				Target:  gardener.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "foo", "kind", "pod"),
			},
			{
				Status:  dikirule.Accepted,
				Message: "foo justify",
				Target:  gardener.NewTarget("cluster", "shoot", "name", "node-local-dns-123!", "namespace", "namespace-test", "kind", "pod", "details", "containerName: test, port: 53"),
			},
			{
				Status:  dikirule.Accepted,
				Message: "Container accepted to use hostPort < 1024.",
				Target:  gardener.NewTarget("cluster", "shoot", "name", "foo", "namespace", "namespace", "kind", "pod", "details", "containerName: test, port: 58"),
			},
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})
})
