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
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ = Describe("#242442", func() {
	var (
		client   client.Client
		plainPod *corev1.Pod
		ctx      = context.TODO()
		digest1  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		digest2  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b854"
		digest3  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b853"
	)

	BeforeEach(func() {
		client = fakeclient.NewClientBuilder().Build()
		plainPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"role": "proxy",
				},
				Namespace: "foo",
			},
			Spec: corev1.PodSpec{
				NodeName: "foo",
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
		r := &rules.Rule242442{Client: client}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		Expect(client.Create(ctx, pod1)).To(Succeed())
		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		pod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		pod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image4@sha256:" + digest1
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("All found images use current versions.", rule.Target{}),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when an image uses more than 1 version", func() {
		r := &rules.Rule242442{Client: client}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		pod1.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       "deployment",
				UID:        "1",
			},
		}
		Expect(client.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image2@sha256:" + digest3
		pod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image3@sha256:" + digest2
		pod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image4@sha256:" + digest1
		pod2.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       "deployment",
				UID:        "1",
			},
		}
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("kind", "Node", "name", "foo", "image", "eu.gcr.io/image2")),
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("kind", "Node", "name", "foo", "image", "eu.gcr.io/image3")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when a pod contains an initContainer", func() {
		r := &rules.Rule242442{Client: client}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		pod1.Spec.InitContainers = []corev1.Container{
			{
				Name: "initFoo",
			},
		}
		pod1.Status.InitContainerStatuses = []corev1.ContainerStatus{
			{
				Name:    "initFoo",
				ImageID: "eu.gcr.io/image10@sha256:" + digest1,
			},
		}
		Expect(client.Create(ctx, pod1)).To(Succeed())
		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		pod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		pod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image4@sha256:" + digest1
		pod2.Spec.InitContainers = []corev1.Container{
			{
				Name: "initFoo",
			},
		}
		pod2.Status.InitContainerStatuses = []corev1.ContainerStatus{
			{
				Name:    "initFoo",
				ImageID: "eu.gcr.io/image10@sha256:" + digest2,
			},
		}
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("kind", "Node", "name", "foo", "image", "eu.gcr.io/image10")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when the image repository includes port number", func() {
		r := &rules.Rule242442{Client: client}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "localhost:7777/image1@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "localhost:7777/image1@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "localhost:7777/image2@sha256:" + digest3
		Expect(client.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "localhost:7777/image2@sha256:" + digest3
		pod2.Status.ContainerStatuses[1].ImageID = "localhost:7777/image3@sha256:" + digest1
		pod2.Status.ContainerStatuses[2].ImageID = "localhost:7777/image3@sha256:" + digest3
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("kind", "Node", "name", "foo", "image", "localhost:7777/image1")),
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("kind", "Node", "name", "foo", "image", "localhost:7777/image3")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return passed results when pods are on different nodes", func() {
		r := &rules.Rule242442{Client: client}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		Expect(client.Create(ctx, pod1)).To(Succeed())
		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image2@sha256:" + digest3
		pod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image3@sha256:" + digest2
		pod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image4@sha256:" + digest1
		pod2.Spec.NodeName = "bar"
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("All found images use current versions.", rule.Target{}),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when options are used", func() {
		r := &rules.Rule242442{
			Client: client,
			Options: &rules.Options242442{
				KubeProxyMatchLabels: map[string]string{
					"foo": "bar",
				},
			},
		}

		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		Expect(client.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Labels["foo"] = "bar"
		pod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image2@sha256:" + digest3
		pod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image3@sha256:" + digest2
		pod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image4@sha256:" + digest1
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("All found images use current versions.", rule.Target{}),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return errored results when containerStatus cannot be found for a given container", func() {
		r := &rules.Rule242442{Client: client}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].Name = "not-found"
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image3@sha256:" + digest3
		Expect(client.Create(ctx, pod1)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.ErroredCheckResult("containerStatus not found for container", rule.NewTarget("container", "foo", "namespace", "foo", "name", "pod1", "kind", "Pod")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return errored result when kube-proxy pods cannot be found", func() {
		kubeProxySelector := labels.SelectorFromSet(labels.Set{"role": "proxy"})
		r := &rules.Rule242442{Client: client}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.ErroredCheckResult("kube-proxy pods not found", rule.NewTarget("selector", kubeProxySelector.String())),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return warning result when the imageID cannot be found for a given container", func() {
		r := &rules.Rule242442{Client: client}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image2@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = ""
		Expect(client.Create(ctx, pod1)).To(Succeed())
		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.WarningCheckResult("ImageID is empty in container status.", rule.NewTarget("container", "foo", "namespace", "foo", "name", "pod1", "kind", "Pod")),
			rule.WarningCheckResult("ImageID is empty in container status.", rule.NewTarget("container", "foobar", "namespace", "foo", "name", "pod1", "kind", "Pod")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return warning results when the image is listed in the allowedImages option", func() {
		r := &rules.Rule242442{Client: client, Options: &rules.Options242442{
			Options242442: &option.Options242442{
				ExpectedVersionedImages: []option.ExpectedVersionedImage{
					{
						Name: "eu.gcr.io/image2",
					},
				},
			},
		},
		}

		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image1@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image2@sha256:" + digest3
		pod1.Spec.InitContainers = []corev1.Container{
			{
				Name: "initFoo",
			},
		}
		pod1.Status.InitContainerStatuses = []corev1.ContainerStatus{
			{
				Name:    "initFoo",
				ImageID: "eu.gcr.io/image2@sha256:" + digest2,
			},
		}
		Expect(client.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Labels["foo"] = "bar"
		pod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image1@sha256:" + digest3
		pod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image4@sha256:" + digest2
		pod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image4@sha256:" + digest1
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("kind", "Node", "name", "foo", "image", "eu.gcr.io/image1")),
			rule.WarningCheckResult("Image is used with more than one versions.", rule.NewTarget("kind", "Node", "name", "foo", "image", "eu.gcr.io/image2")),
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("kind", "Node", "name", "foo", "image", "eu.gcr.io/image4")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
})
