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

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ = Describe("#242414", func() {
	var (
		client        client.Client
		options       option.Options242414
		plainPod      *corev1.Pod
		ctx           = context.TODO()
		namespaceName = "foo"
		namespace     *corev1.Namespace
	)

	BeforeEach(func() {
		client = fakeclient.NewClientBuilder().Build()

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
		r := &rules.Rule242414{Client: client, Options: &options}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		Expect(client.Create(ctx, pod1)).To(Succeed())
		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Container does not use hostPort < 1024.",
				Target:  rule.NewTarget("name", "pod1", "namespace", "foo", "kind", "pod"),
			},
			{
				Status:  rule.Passed,
				Message: "Container does not use hostPort < 1024.",
				Target:  rule.NewTarget("name", "pod2", "namespace", "foo", "kind", "pod"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when a pod fails", func() {
		r := &rules.Rule242414{Client: client, Options: &options}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		Expect(client.Create(ctx, pod1)).To(Succeed())
		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Spec.Containers[0].Ports[0].HostPort = 1011
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Container does not use hostPort < 1024.",
				Target:  rule.NewTarget("name", "pod1", "namespace", "foo", "kind", "pod"),
			},
			{
				Status:  rule.Failed,
				Message: "Container uses hostPort < 1024.",
				Target:  rule.NewTarget("name", "pod2", "namespace", "foo", "kind", "pod", "details", "containerName: test, port: 1011"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when options are present", func() {
		options = option.Options242414{
			AcceptedPods: []option.AcceptedPods242414{
				{
					PodMatchLabels:       map[string]string{"foo": "bar"},
					NamespaceMatchLabels: map[string]string{"foo": "not-bar"},
					Ports:                []int32{58},
				},
				{
					PodMatchLabels:       map[string]string{"foo": "bar"},
					NamespaceMatchLabels: map[string]string{"foo": "bar"},
					Justification:        "foo justify",
					Ports:                []int32{53},
				},
			},
		}

		r := &rules.Rule242414{Client: client, Options: &options}

		acceptedShootPod := plainPod.DeepCopy()
		acceptedShootPod.Name = "accepted-shoot-pod"
		acceptedShootPod.Spec.Containers[0].Ports[0].HostPort = 53

		notAcceptedShootPod := plainPod.DeepCopy()
		notAcceptedShootPod.Name = "not-accepted-shoot-pod"
		notAcceptedShootPod.Spec.Containers[0].Ports[0].HostPort = 58

		Expect(client.Create(ctx, namespace)).To(Succeed())
		Expect(client.Create(ctx, acceptedShootPod)).To(Succeed())
		Expect(client.Create(ctx, notAcceptedShootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Accepted,
				Message: "foo justify",
				Target:  rule.NewTarget("name", "accepted-shoot-pod", "namespace", "foo", "kind", "pod", "details", "containerName: test, port: 53"),
			},
			{
				Status:  rule.Failed,
				Message: "Container uses hostPort < 1024.",
				Target:  rule.NewTarget("name", "not-accepted-shoot-pod", "namespace", "foo", "kind", "pod", "details", "containerName: test, port: 58"),
			},
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})
})
