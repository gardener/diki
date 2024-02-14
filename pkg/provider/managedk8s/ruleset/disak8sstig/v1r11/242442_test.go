// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242442", func() {
	var (
		client   client.Client
		plainPod *corev1.Pod
		ctx      = context.TODO()
	)

	BeforeEach(func() {
		client = fakeclient.NewClientBuilder().Build()
		plainPod = &corev1.Pod{
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
		r := &v1r11.Rule242442{Client: client}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:foobar"
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:foo"
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:bar"
		Expect(client.Create(ctx, pod1)).To(Succeed())
		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image2@sha256:foo"
		pod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image3@sha256:bar"
		pod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image4@sha256:foobar"
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("All found images use current versions.", rule.Target{}),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when a image uses more than 1 version", func() {
		r := &v1r11.Rule242442{Client: client}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:foobar"
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:foo"
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:bar"
		Expect(client.Create(ctx, pod1)).To(Succeed())
		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image2@sha256:bar"
		pod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image3@sha256:foo"
		pod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image4@sha256:foobar"
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("image", "eu.gcr.io/image2")),
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("image", "eu.gcr.io/image3")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return errored results when containerStatus cannot be found for a given container", func() {
		r := &v1r11.Rule242442{Client: client}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].Name = "not-found"
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:foo"
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:bar"
		Expect(client.Create(ctx, pod1)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.ErroredCheckResult("containerStatus not found for container", rule.NewTarget("container", "foo", "namespace", "", "name", "pod1", "kind", "pod")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
})
