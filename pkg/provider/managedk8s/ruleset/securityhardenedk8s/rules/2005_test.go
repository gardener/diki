// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
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
			AllowedRepositories: []rules.AllowedRepository{},
		}
	})

	It("should error when rule options are missing", func() {
		Expect(client.Create(ctx, pod)).To(Succeed())

		r := &rules.Rule2005{Client: client}
		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.ErroredCheckResult("rule options are missing, but required", nil),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should fail when images are not from allowed list", func() {
		option.AllowedRepositories = append(option.AllowedRepositories, rules.AllowedRepository{
			Prefix: "foo",
		})
		r := &rules.Rule2005{Client: client, Options: &option}
		Expect(client.Create(ctx, pod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image comes from not allowed repository.", rule.NewTarget("kind", "pod", "name", "foo", "namespace", "bar", "container", "foo", "imageBase", "eu.gcr.io/image")),
			rule.FailedCheckResult("Image comes from not allowed repository.", rule.NewTarget("kind", "pod", "name", "foo", "namespace", "bar", "container", "bar", "imageBase", "eu.gcr.io/foo/image")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should pass when images are from allowed list", func() {
		option.AllowedRepositories = append(option.AllowedRepositories, rules.AllowedRepository{
			Prefix: "eu.gcr.io/",
		})
		r := &rules.Rule2005{Client: client, Options: &option}
		Expect(client.Create(ctx, pod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("Image comes from allowed repository.", rule.NewTarget("kind", "pod", "name", "foo", "namespace", "bar", "container", "foo", "imageBase", "eu.gcr.io/image")),
			rule.PassedCheckResult("Image comes from allowed repository.", rule.NewTarget("kind", "pod", "name", "foo", "namespace", "bar", "container", "bar", "imageBase", "eu.gcr.io/foo/image")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
	It("should return correct results when not all images pass", func() {
		option.AllowedRepositories = append(option.AllowedRepositories, rules.AllowedRepository{
			Prefix: "eu.gcr.io/foo",
		})
		r := &rules.Rule2005{Client: client, Options: &option}
		Expect(client.Create(ctx, pod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Image comes from not allowed repository.", rule.NewTarget("kind", "pod", "name", "foo", "namespace", "bar", "container", "foo", "imageBase", "eu.gcr.io/image")),
			rule.PassedCheckResult("Image comes from allowed repository.", rule.NewTarget("kind", "pod", "name", "foo", "namespace", "bar", "container", "bar", "imageBase", "eu.gcr.io/foo/image")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	Describe("#ValidateOptions2005", func() {
		It("should deny empty allowed repositories list", func() {
			options := rules.Options2005{}

			result := options.Validate()

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("allowedRepositories"),
					"Detail": Equal("must not be empty"),
				})),
			))
		})

		It("should correctly validate options", func() {
			options := rules.Options2005{
				AllowedRepositories: []rules.AllowedRepository{
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
					"Field":  Equal("allowedRepositories[1].prefix"),
					"Detail": Equal("must not be empty"),
				})),
			))
		})
	})
})
