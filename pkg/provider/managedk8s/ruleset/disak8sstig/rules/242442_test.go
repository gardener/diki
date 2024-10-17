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
		pod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image-one@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image-two@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image-three@sha256:" + digest3
		Expect(client.Create(ctx, pod1)).To(Succeed())
		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image-two@sha256:" + digest2
		pod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image-three@sha256:" + digest3
		pod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image-four@sha256:" + digest1
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
		pod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image-one@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image-two@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image-three@sha256:" + digest3
		Expect(client.Create(ctx, pod1)).To(Succeed())
		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image-two@sha256:" + digest3
		pod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image-three@sha256:" + digest2
		pod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image-four@sha256:" + digest1
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("kind", "node", "name", "foo", "image", "eu.gcr.io/image-two")),
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("kind", "node", "name", "foo", "image", "eu.gcr.io/image-three")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when an image uses more than 1 version #2", func() {
		r := &rules.Rule242442{Client: client}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "localhost:7777/image-one@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "localhost:7777/image-one@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "localhost:7777/image-two@sha256:" + digest3
		Expect(client.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "localhost:7777/image-two@sha256:" + digest3
		pod2.Status.ContainerStatuses[1].ImageID = "localhost:7777/image-three@sha256:" + digest1
		pod2.Status.ContainerStatuses[2].ImageID = "localhost:7777/image-three@sha256:" + digest3
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("kind", "node", "name", "foo", "image", "localhost:7777/image-one")),
			rule.FailedCheckResult("Image is used with more than one versions.", rule.NewTarget("kind", "node", "name", "foo", "image", "localhost:7777/image-three")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return passed results when pods are on different nodes", func() {
		r := &rules.Rule242442{Client: client}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image-one@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image-two@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image-three@sha256:" + digest3
		Expect(client.Create(ctx, pod1)).To(Succeed())
		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image-two@sha256:" + digest3
		pod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image-three@sha256:" + digest2
		pod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image-four@sha256:" + digest1
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
		pod1.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image-one@sha256:" + digest1
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image-two@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image-three@sha256:" + digest3
		Expect(client.Create(ctx, pod1)).To(Succeed())
		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Labels["foo"] = "bar"
		pod2.Status.ContainerStatuses[0].ImageID = "eu.gcr.io/image-two@sha256:" + digest3
		pod2.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image-three@sha256:" + digest2
		pod2.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image-four@sha256:" + digest1
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
		pod1.Status.ContainerStatuses[1].ImageID = "eu.gcr.io/image-two@sha256:" + digest2
		pod1.Status.ContainerStatuses[2].ImageID = "eu.gcr.io/image-three@sha256:" + digest3
		Expect(client.Create(ctx, pod1)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.ErroredCheckResult("containerStatus not found for container", rule.NewTarget("container", "foo", "namespace", "", "name", "pod1", "kind", "pod")),
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
})
