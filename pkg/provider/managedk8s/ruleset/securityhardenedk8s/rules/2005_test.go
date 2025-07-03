// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s/rules"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#2005", func() {
	var (
		client client.Client
		pod    *corev1.Pod
		option rules.Options2005
		ctx    = context.TODO()
		digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	)

	BeforeEach(func() {
		client = fakeclient.NewClientBuilder().Build()
		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "bar",
				Labels: map[string]string{
					"foo": "bar",
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
				},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:    "foo",
						ImageID: "eu.gcr.io/image@sha256:" + digest,
					},
					{
						Name:    "bar",
						ImageID: "eu.gcr.io/foo/image@sha256:" + digest,
					},
				},
			},
		}
		option = rules.Options2005{
			AllowedImages: []rules.AllowedImage{},
		}
	})

	It("should fail when rule options are missing", func() {
		Expect(client.Create(ctx, pod)).To(Succeed())

		r := &rules.Rule2005{Client: client}
		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("There are no allowed images in rule options.", nil),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should fail when images are not from allowed list", func() {
		option.AllowedImages = append(option.AllowedImages, rules.AllowedImage{
			Prefix: "foo",
		})
		r := &rules.Rule2005{Client: client, Options: &option}
		Expect(client.Create(ctx, pod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image has not allowed prefix.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar", "container", "foo", "imageRef", "eu.gcr.io/image@sha256:"+digest)),
			rule.FailedCheckResult("Image has not allowed prefix.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar", "container", "bar", "imageRef", "eu.gcr.io/foo/image@sha256:"+digest)),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should pass when no pods are present in the cluster", func() {
		option.AllowedImages = append(option.AllowedImages, rules.AllowedImage{
			Prefix: "foo",
		})
		r := &rules.Rule2005{Client: client, Options: &option}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("The cluster does not have any Pods.", rule.NewTarget()),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should pass when images are from allowed list", func() {
		option.AllowedImages = append(option.AllowedImages, rules.AllowedImage{
			Prefix: "eu.gcr.io/",
		})
		r := &rules.Rule2005{Client: client, Options: &option}
		Expect(client.Create(ctx, pod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("Image has allowed prefix.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar", "container", "foo", "imageRef", "eu.gcr.io/image@sha256:"+digest)),
			rule.PassedCheckResult("Image has allowed prefix.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar", "container", "bar", "imageRef", "eu.gcr.io/foo/image@sha256:"+digest)),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should warn when imageID is empty", func() {
		option.AllowedImages = append(option.AllowedImages, rules.AllowedImage{
			Prefix: "eu.gcr.io/foo",
		})
		pod.Status.ContainerStatuses[0].ImageID = ""
		r := &rules.Rule2005{Client: client, Options: &option}
		Expect(client.Create(ctx, pod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.WarningCheckResult("ImageID is empty in container status.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar", "container", "foo")),
			rule.PassedCheckResult("Image has allowed prefix.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar", "container", "bar", "imageRef", "eu.gcr.io/foo/image@sha256:"+digest)),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when an initContainer is present", func() {
		option.AllowedImages = append(option.AllowedImages, rules.AllowedImage{
			Prefix: "eu.gcr.io/",
		})
		pod.Spec.InitContainers = []corev1.Container{
			{
				Name: "initFoo",
			},
		}
		pod.Status.InitContainerStatuses = []corev1.ContainerStatus{
			{
				Name:    "initFoo",
				ImageID: "eu.gcr/image@sha256:" + digest,
			},
		}
		r := &rules.Rule2005{Client: client, Options: &option}
		Expect(client.Create(ctx, pod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("Image has allowed prefix.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar", "container", "foo", "imageRef", "eu.gcr.io/image@sha256:"+digest)),
			rule.PassedCheckResult("Image has allowed prefix.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar", "container", "bar", "imageRef", "eu.gcr.io/foo/image@sha256:"+digest)),
			rule.FailedCheckResult("Image has not allowed prefix.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar", "container", "initFoo", "imageRef", "eu.gcr/image@sha256:"+digest)),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when an initContainer is present", func() {
		option.AllowedImages = append(option.AllowedImages, rules.AllowedImage{
			Prefix: "eu.gcr.io/",
		})
		pod.Spec.InitContainers = []corev1.Container{
			{
				Name: "initFoo",
			},
		}
		pod.Status.InitContainerStatuses = []corev1.ContainerStatus{
			{
				Name:    "initFoo",
				ImageID: "eu.gcr/image@sha256:" + digest,
			},
		}
		r := &rules.Rule2005{Client: client, Options: &option}
		Expect(client.Create(ctx, pod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("Image has allowed prefix.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar", "container", "foo", "imageRef", "eu.gcr.io/image@sha256:"+digest)),
			rule.PassedCheckResult("Image has allowed prefix.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar", "container", "bar", "imageRef", "eu.gcr.io/foo/image@sha256:"+digest)),
			rule.FailedCheckResult("Image has not allowed prefix.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar", "container", "initFoo", "imageRef", "eu.gcr/image@sha256:"+digest)),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct targets when pods have owner references", func() {
		r := &rules.Rule2005{Client: client, Options: &rules.Options2005{}}

		replicaSet := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "foo",
				UID:       "1",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       "Deployment",
						Name:       "foo",
					},
				},
			},
		}
		Expect(client.Create(ctx, replicaSet)).To(Succeed())

		pod1 := pod.DeepCopy()
		pod1.Name = "foo-bar"
		pod1.Namespace = "foo"
		pod1.OwnerReferences = []metav1.OwnerReference{
			{
				UID:        "1",
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "ReplicaSet",
			},
		}
		Expect(client.Create(ctx, pod1)).To(Succeed())

		pod2 := pod.DeepCopy()
		pod2.Name = "foo-baz"
		pod2.Namespace = "foo"
		pod2.OwnerReferences = []metav1.OwnerReference{
			{
				UID:        "2",
				APIVersion: "apps/v1",
				Kind:       "DaemonSet",
				Name:       "bar",
			},
		}
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(ruleResult.CheckResults).To(Equal(
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Image has not allowed prefix.", Target: rule.NewTarget("kind", "Deployment", "name", "foo", "namespace", "foo", "container", "foo", "imageRef", "eu.gcr.io/image@sha256:"+digest)},
				{Status: rule.Failed, Message: "Image has not allowed prefix.", Target: rule.NewTarget("kind", "Deployment", "name", "foo", "namespace", "foo", "container", "bar", "imageRef", "eu.gcr.io/foo/image@sha256:"+digest)},
				{Status: rule.Failed, Message: "Image has not allowed prefix.", Target: rule.NewTarget("kind", "DaemonSet", "name", "bar", "namespace", "foo", "container", "foo", "imageRef", "eu.gcr.io/image@sha256:"+digest)},
				{Status: rule.Failed, Message: "Image has not allowed prefix.", Target: rule.NewTarget("kind", "DaemonSet", "name", "bar", "namespace", "foo", "container", "bar", "imageRef", "eu.gcr.io/foo/image@sha256:"+digest)},
			},
		))
	})

	Describe("#ValidateOptions2005", func() {
		It("should deny empty allowed images list", func() {
			options := rules.Options2005{}

			result := options.Validate()

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("allowedImages"),
					"Detail": Equal("must not be empty"),
				})),
			))
		})

		It("should correctly validate options", func() {
			options := rules.Options2005{
				AllowedImages: []rules.AllowedImage{
					{
						Prefix: "foo",
					},
					{
						Prefix: "",
					},
					{
						Prefix: "bar",
					},
				},
			}

			result := options.Validate()

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("allowedImages[1].prefix"),
					"Detail": Equal("must not be empty"),
				})),
			))
		})
	})
})
