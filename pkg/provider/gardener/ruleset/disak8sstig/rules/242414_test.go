// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
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

	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
	disaoption "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ = Describe("#242414", func() {
	var (
		fakeSeedClient     client.Client
		fakeShootClient    client.Client
		options            disaoption.Options242414
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
				Namespace: shootNamespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
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
		r := &rules.Rule242414{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: seedNamespaceName, Options: &options}
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not have container using hostPort < 1024.",
				Target:  rule.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "seed", "kind", "Pod"),
			},
			{
				Status:  rule.Passed,
				Message: "Pod does not have container using hostPort < 1024.",
				Target:  rule.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "shoot", "kind", "Pod"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when a pod fails", func() {
		r := &rules.Rule242414{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: seedNamespaceName, Options: &options}
		shootPod.Spec.Containers[0].Ports[0].HostPort = 1011
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not have container using hostPort < 1024.",
				Target:  rule.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "seed", "kind", "Pod"),
			},
			{
				Status:  rule.Failed,
				Message: "Pod has container using hostPort < 1024.",
				Target:  rule.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "shoot", "kind", "Pod", "container", "test", "details", "port: 1011"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when a pod contains an initContainer", func() {
		r := &rules.Rule242414{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: seedNamespaceName, Options: &options}
		shootPod.Spec.InitContainers = []corev1.Container{
			{
				Name: "initFoo",
				Ports: []corev1.ContainerPort{
					{
						HostPort: 42,
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
				Message: "Pod does not have container using hostPort < 1024.",
				Target:  rule.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "seed", "kind", "Pod"),
			},
			{
				Status:  rule.Failed,
				Message: "Pod has container using hostPort < 1024.",
				Target:  rule.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "shoot", "kind", "Pod", "container", "initFoo", "details", "port: 42"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when options are present", func() {
		options = disaoption.Options242414{
			AcceptedPods: []disaoption.AcceptedPods242414{
				{
					AcceptedNamespacedObject: option.AcceptedNamespacedObject{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
							NamespaceLabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "not-bar"},
							},
						},
					},
					Ports: []int32{58},
				},
				{
					AcceptedNamespacedObject: option.AcceptedNamespacedObject{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
							NamespaceLabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
						Justification: "foo justify",
					},
					Ports: []int32{53},
				},
			},
		}

		r := &rules.Rule242414{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: seedNamespaceName, Options: &options}

		acceptedShootPod := shootPod.DeepCopy()
		acceptedShootPod.Name = "accepted-shoot-pod"
		acceptedShootPod.Spec.Containers[0].Ports[0].HostPort = 53

		notAcceptedShootPod := shootPod.DeepCopy()
		notAcceptedShootPod.Name = "not-accepted-shoot-pod"
		notAcceptedShootPod.Spec.Containers[0].Ports[0].HostPort = 58

		Expect(fakeSeedClient.Create(ctx, seedNamespace)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootNamespace)).To(Succeed())
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, acceptedShootPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, notAcceptedShootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not have container using hostPort < 1024.",
				Target:  rule.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "seed", "kind", "Pod"),
			},
			{
				Status:  rule.Accepted,
				Message: "foo justify",
				Target:  rule.NewTarget("cluster", "shoot", "name", "accepted-shoot-pod", "namespace", "shoot", "kind", "Pod", "container", "test", "details", "port: 53"),
			},
			{
				Status:  rule.Failed,
				Message: "Pod has container using hostPort < 1024.",
				Target:  rule.NewTarget("cluster", "shoot", "name", "not-accepted-shoot-pod", "namespace", "shoot", "kind", "Pod", "container", "test", "details", "port: 58"),
			},
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})
})
