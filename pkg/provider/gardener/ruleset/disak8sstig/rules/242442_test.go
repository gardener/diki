// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ = Describe("#242442", func() {
	var (
		fakeSeedClient  client.Client
		fakeShootClient client.Client
		seedPod         *corev1.Pod
		shootPod        *corev1.Pod
		ctx             = context.TODO()
		namespace       = "foo"
		digest1         = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		digest2         = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b854"
		digest3         = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b853"
		options         *rules.Options242442
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
				InitContainers: []corev1.Container{
					{
						Name: "initFoo",
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
				InitContainerStatuses: []corev1.ContainerStatus{
					{
						Name: "initFoo",
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
				InitContainers: []corev1.Container{
					{
						Name: "initFoo",
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
				InitContainerStatuses: []corev1.ContainerStatus{
					{
						Name: "initFoo",
					},
				},
			},
		}
		options = &rules.Options242442{}
	})

	It("should return correct results when all images use only 1 version", func() {
		r := &rules.Rule242442{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace}
		seedPod.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest1
		seedPod.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		seedPod.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		seedPod.Status.InitContainerStatuses[0].ImageID = "eu.gcr.io/image10@sha256:" + digest1
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		shootPod1 := shootPod.DeepCopy()
		shootPod1.Name = "shoot-pod1"
		shootPod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest1
		shootPod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		shootPod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		shootPod1.Status.InitContainerStatuses[0].ImageID = "eu.gcr.io/image10@sha256:" + digest2
		Expect(fakeShootClient.Create(ctx, shootPod1)).To(Succeed())
		shootPod2 := shootPod.DeepCopy()
		shootPod2.Name = "shoot-pod2"
		shootPod2.Namespace = "bar"
		shootPod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image2@sha256:" + digest3
		shootPod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image3@sha256:" + digest2
		shootPod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image4@sha256:" + digest1
		shootPod2.Status.InitContainerStatuses[0].ImageID = "eu.gcr.io/image10@sha256:" + digest2
		Expect(fakeShootClient.Create(ctx, shootPod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("All found images use current versions.", rule.Target{}),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})
	It("should return correct results when an image uses more than 1 version", func() {
		r := &rules.Rule242442{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace}
		shootPod1 := shootPod.DeepCopy()
		shootPod1.Name = "shoot-pod1"
		shootPod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest1
		shootPod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		shootPod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		shootPod1.Status.InitContainerStatuses[0].ImageID = "eu.gcr.io/image10@sha256:" + digest2
		Expect(fakeShootClient.Create(ctx, shootPod1)).To(Succeed())
		shootPod2 := shootPod.DeepCopy()
		shootPod2.Name = "shoot-pod2"
		shootPod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image2@sha256:" + digest3
		shootPod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image3@sha256:" + digest2
		shootPod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image4@sha256:" + digest1
		shootPod2.Status.InitContainerStatuses[0].ImageID = "eu.gcr.io/image10@sha256:" + digest3
		Expect(fakeShootClient.Create(ctx, shootPod2)).To(Succeed())
		seedPod1 := seedPod.DeepCopy()
		seedPod1.Name = "seed-pod1"
		seedPod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest2
		seedPod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest3
		seedPod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest1
		seedPod1.Status.InitContainerStatuses[0].ImageID = "eu.gcr.io/image10@sha256:" + digest1
		Expect(fakeSeedClient.Create(ctx, seedPod1)).To(Succeed())
		seedPod2 := seedPod.DeepCopy()
		seedPod2.Name = "seed-pod2"
		seedPod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image2@sha256:" + digest3
		seedPod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image3@sha256:" + digest2
		seedPod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image4@sha256:" + digest1
		seedPod2.Status.InitContainerStatuses[0].ImageID = "eu.gcr.io/image10@sha256:" + digest2
		Expect(fakeSeedClient.Create(ctx, seedPod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("cluster", "seed", "image", "eu.gcr.io/image3", "namespace", "foo")),
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("cluster", "shoot", "image", "eu.gcr.io/image2", "namespace", "foo")),
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("cluster", "shoot", "image", "eu.gcr.io/image3", "namespace", "foo")),
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("cluster", "seed", "image", "eu.gcr.io/image10", "namespace", "foo")),
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("cluster", "shoot", "image", "eu.gcr.io/image10", "namespace", "foo")),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})
	It("should return correct results when the image repository includes port number", func() {
		r := &rules.Rule242442{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace}
		pod1 := shootPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "localhost:7777/image1@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "localhost:7777/image1@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "localhost:7777/image2@sha256:" + digest3
		pod1.Status.InitContainerStatuses[0].ImageID = "localhost:7777/image10@sha256:" + digest1
		Expect(fakeShootClient.Create(ctx, pod1)).To(Succeed())

		pod2 := seedPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "localhost:7777/image2@sha256:" + digest3
		pod2.Status.ContainerStatuses[1].ImageID = "localhost:7777/image3@sha256:" + digest1
		pod2.Status.ContainerStatuses[2].ImageID = "localhost:7777/image3@sha256:" + digest3
		pod2.Status.InitContainerStatuses[0].ImageID = "localhost:7777/image10@sha256:" + digest1
		Expect(fakeSeedClient.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("cluster", "seed", "image", "localhost:7777/image3", "namespace", seedPod.Namespace)),
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("cluster", "shoot", "image", "localhost:7777/image1", "namespace", shootPod.Namespace)),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})
	It("should return errored results when containerStatus cannot be found for a given container", func() {
		r := &rules.Rule242442{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace}
		seedPod.Status.ContainerStatuses[0].Name = "not-foo"
		seedPod.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		seedPod.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		seedPod.Status.InitContainerStatuses[0].ImageID = "eu.gcr.io/image10@sha256:" + digest1
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.ErroredCheckResult("containerStatus not found for container", rule.NewTarget("cluster", "seed", "namespace", "foo", "container", "foo", "name", "seed-pod", "kind", "Pod")),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return warning result when the imageID cannot be found for a given container", func() {
		r := &rules.Rule242442{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace}
		seedPod.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		seedPod.Status.ContainerStatuses[2].ImageID = ""
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.WarningCheckResult("ImageID is empty in container status.", rule.NewTarget("cluster", "seed", "namespace", "foo", "container", "foo", "name", "seed-pod", "kind", "Pod")),
			rule.WarningCheckResult("ImageID is empty in container status.", rule.NewTarget("cluster", "seed", "namespace", "foo", "container", "foobar", "name", "seed-pod", "kind", "Pod")),
			rule.WarningCheckResult("ImageID is empty in container status.", rule.NewTarget("cluster", "seed", "namespace", "foo", "container", "initFoo", "name", "seed-pod", "kind", "Pod")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return warning results when the image is listed in the allowedImages options", func() {
		options.AllowedImages = []option.AllowedImage{
			{
				Name: "localhost:7777/image1",
			},
		}
		r := &rules.Rule242442{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace, Options: options}
		pod1 := shootPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[1].ImageID = "localhost:7777/image1@sha256:" + digest2
		pod1.Status.ContainerStatuses[0].ImageID = "localhost:7777/image1@sha256:" + digest1
		pod1.Status.ContainerStatuses[2].ImageID = "localhost:7777/image10@sha256:" + digest3
		pod1.Status.InitContainerStatuses[0].ImageID = "localhost:7777/image10@sha256:" + digest1
		Expect(fakeShootClient.Create(ctx, pod1)).To(Succeed())

		pod2 := seedPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "localhost:7778/image2@sha256:" + digest3
		pod2.Status.ContainerStatuses[1].ImageID = "localhost:7778/image3@sha256:" + digest1
		pod2.Status.ContainerStatuses[2].ImageID = "localhost:7778/image3@sha256:" + digest3
		pod2.Status.InitContainerStatuses[0].ImageID = "localhost:7777/image10@sha256:" + digest1
		Expect(fakeSeedClient.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		Expect(ruleResult.CheckResults).To(Equal(
			[]rule.CheckResult{
				rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("cluster", "seed", "image", "localhost:7778/image3", "namespace", seedPod.Namespace)),
				rule.WarningCheckResult("Image is used with more than one versions.", rule.NewTarget("cluster", "shoot", "image", "localhost:7777/image1", "namespace", shootPod.Namespace)),
				rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("cluster", "shoot", "image", "localhost:7777/image10", "namespace", shootPod.Namespace)),
			},
		))
	})

	It("should return correct targets when the pods have owner references", func() {
		r := &rules.Rule242442{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: namespace}

		seedReplicaSet := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "seedReplicaSet",
				UID:       "1",
				Namespace: namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       "Deployment",
						Name:       "seedFoo",
					},
				},
			},
		}
		Expect(fakeSeedClient.Create(ctx, seedReplicaSet)).To(Succeed())

		seedPod1 := seedPod.DeepCopy()
		seedPod1.Name = "seed-pod-1"
		seedPod1.OwnerReferences = []metav1.OwnerReference{
			{
				UID:        "1",
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "ReplicaSet",
			},
		}
		seedPod1.Status.ContainerStatuses[1].ImageID = ""
		seedPod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		Expect(fakeSeedClient.Create(ctx, seedPod1)).To(Succeed())

		seedPod2 := seedPod.DeepCopy()
		seedPod2.Name = "seed-pod-2"
		seedPod2.OwnerReferences = []metav1.OwnerReference{
			{
				UID:        "1",
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "ReplicaSet",
			},
		}
		seedPod2.Status.ContainerStatuses[1].ImageID = ""
		seedPod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		Expect(fakeSeedClient.Create(ctx, seedPod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			rule.WarningCheckResult("ImageID is empty in container status.", rule.NewTarget("cluster", "seed", "namespace", "foo", "container", "foo", "name", "seedFoo", "kind", "Deployment")),
			rule.WarningCheckResult("ImageID is empty in container status.", rule.NewTarget("cluster", "seed", "namespace", "foo", "container", "bar", "name", "seedFoo", "kind", "Deployment")),
			rule.WarningCheckResult("ImageID is empty in container status.", rule.NewTarget("cluster", "seed", "namespace", "foo", "container", "initFoo", "name", "seedFoo", "kind", "Deployment")),
		}))
	})
})
