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

	"github.com/gardener/diki/pkg/provider/virtualgarden/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ = Describe("#242442", func() {
	var (
		fakeClient client.Client
		pod        *corev1.Pod
		ctx        = context.TODO()
		namespace  = "foo"
		digest1    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		digest2    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b854"
		digest3    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b853"
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod",
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
	})

	It("should return correct results when all images use only 1 version", func() {
		r := &rules.Rule242442{Client: fakeClient, Namespace: namespace}
		pod.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest1
		pod.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		pod.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		Expect(fakeClient.Create(ctx, pod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("All found images use current versions.", rule.Target{}),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when an image uses more than 1 version", func() {
		r := &rules.Rule242442{Client: fakeClient, Namespace: namespace}
		pod.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest1
		pod.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		pod.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image2@sha256:" + digest3
		Expect(fakeClient.Create(ctx, pod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("image", "eu.gcr.io/image2")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when a pod contains an initContainer", func() {
		r := &rules.Rule242442{Client: fakeClient, Namespace: namespace}
		pod.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest1
		pod.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		pod.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		pod.Spec.InitContainers = []corev1.Container{
			{
				Name: "initFoo",
			},
			{
				Name: "initFoo2",
			},
		}
		pod.Status.InitContainerStatuses = []corev1.ContainerStatus{
			{
				Name:    "initFoo",
				ImageID: "eu.gcr.io/image10@sha256:" + digest1,
			},
			{
				Name:    "initFoo2",
				ImageID: "eu.gcr.io/image10@sha256:" + digest2,
			},
		}
		Expect(fakeClient.Create(ctx, pod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("image", "eu.gcr.io/image10")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when the image repository includes port number", func() {
		r := &rules.Rule242442{Client: fakeClient, Namespace: namespace}
		pod1 := pod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "localhost:7777/image1@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "localhost:7777/image1@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "localhost:7777/image2@sha256:" + digest3
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := pod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "localhost:7777/image2@sha256:" + digest3
		pod2.Status.ContainerStatuses[1].ImageID = "localhost:7777/image3@sha256:" + digest1
		pod2.Status.ContainerStatuses[2].ImageID = "localhost:7777/image3@sha256:" + digest3
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("image", "localhost:7777/image1")),
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("image", "localhost:7777/image3")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return errored results when containerStatus cannot be found for a given container", func() {
		r := &rules.Rule242442{Client: fakeClient, Namespace: namespace}
		pod.Status.ContainerStatuses[0].Name = "not-foo"
		pod.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest1
		pod.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest2
		pod.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       "deployment",
			},
		}
		Expect(fakeClient.Create(ctx, pod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.ErroredCheckResult("containerStatus not found for container", rule.NewTarget("container", "foo", "name", "deployment", "kind", "Deployment", "namespace", "foo")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return warning result when the imageID cannot be found for a given container", func() {
		r := &rules.Rule242442{Client: fakeClient, Namespace: namespace}
		pod.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest1
		pod.Status.ContainerStatuses[2].ImageID = ""
		Expect(fakeClient.Create(ctx, pod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.WarningCheckResult("ImageID is empty in container status.", rule.NewTarget("container", "foo", "name", "pod", "kind", "Pod", "namespace", "foo")),
			rule.WarningCheckResult("ImageID is empty in container status.", rule.NewTarget("container", "foobar", "name", "pod", "kind", "Pod", "namespace", "foo")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return warning results when the image is listed in the expectedVersionedImages option", func() {
		r := &rules.Rule242442{Client: fakeClient, Namespace: namespace,
			Options: &option.Options242442{
				ExpectedVersionedImages: []option.ExpectedVersionedImage{
					{
						Name: "localhost:7777/image2",
					},
				},
			},
		}

		pod1 := pod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "localhost:7777/image1@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "localhost:7777/image1@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "localhost:7777/image2@sha256:" + digest3
		pod1.Spec.InitContainers = []corev1.Container{
			{
				Name: "initFoo",
			},
		}
		pod1.Status.InitContainerStatuses = []corev1.ContainerStatus{
			{
				Name:    "initFoo",
				ImageID: "localhost:7777/image2@sha256:" + digest2,
			},
		}
		pod1.Status.ContainerStatuses[2].ImageID = "localhost:7777/image2@sha256:" + digest3
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := pod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "localhost:7777/image2@sha256:" + digest3
		pod2.Status.ContainerStatuses[1].ImageID = "localhost:7777/image3@sha256:" + digest1
		pod2.Status.ContainerStatuses[2].ImageID = "localhost:7777/image3@sha256:" + digest1
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("image", "localhost:7777/image1")),
			rule.WarningCheckResult("Image is used with more than one versions.", rule.NewTarget("image", "localhost:7777/image2")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

})
