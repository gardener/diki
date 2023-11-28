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

var _ = Describe("#242442", func() {
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
						Name: "foo",
					},
					{
						Name: "bar",
					},
					{
						Name: "foobar",
					},
				},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name: "foo",
					},
					{
						Name: "bar",
					},
					{
						Name: "foobar",
					},
				},
			},
		}
		shootPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shoot-pod",
				Namespace: namespace,
				Labels: map[string]string{
					"resources.gardener.cloud/managed-by": "gardener",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "foo",
					},
					{
						Name: "bar",
					},
					{
						Name: "foobar",
					},
				},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name: "foo",
					},
					{
						Name: "bar",
					},
					{
						Name: "foobar",
					},
				},
			},
		}
	})

	It("should return correct results when all images use only 1 version", func() {
		r := &v1r11.Rule242442{Logger: testLogger, ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace}
		seedPod.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:foobar"
		seedPod.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:foo"
		seedPod.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:bar"
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		shootPod.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image2@sha256:foo"
		shootPod.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image3@sha256:bar"
		shootPod.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image4@sha256:foobar"
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("All found images use current versions.", rule.Target{}),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when a image uses more than 1 version", func() {
		r := &v1r11.Rule242442{Logger: testLogger, ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace}
		seedPod.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:foobar"
		seedPod.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:foo"
		seedPod.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:bar"
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		shootPod.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image2@sha256:bar"
		shootPod.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image3@sha256:foo"
		shootPod.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image4@sha256:foobar"
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("image", "eu.gcr.io/image2")),
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("image", "eu.gcr.io/image3")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return errored results when containerStatus cannot be found for a given container", func() {
		r := &v1r11.Rule242442{Logger: testLogger, ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace}
		seedPod.Status.ContainerStatuses[0].Name = "not-foo"
		seedPod.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:foo"
		seedPod.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:bar"
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.ErroredCheckResult("containerStatus not found for container", rule.NewTarget("cluster", "seed", "container", "foo", "name", "seed-pod", "kind", "pod")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
})
