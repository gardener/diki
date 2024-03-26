// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11_test

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

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ = Describe("#242417", func() {
	var (
		fakeClient client.Client
		plainPod   *corev1.Pod
		options    *v1r11.Options242417
		ctx        = context.TODO()
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		plainPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "foo",
				Labels:    map[string]string{},
			},
		}
		options = &v1r11.Options242417{
			AcceptedPods: []v1r11.AcceptedPods242417{
				{
					PodMatchLabels: map[string]string{},
					NamespaceNames: []string{"kube-system", "kube-public", "kube-node-lease"},
				},
			},
		}
	})

	It("should return passed checkResult when no user pods are present in system namespaces", func() {
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "bar"
		pod2.Namespace = "kube-system"
		pod2.Labels["label"] = "value"
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		pod3 := plainPod.DeepCopy()
		pod3.Name = "bar"
		pod3.Namespace = "kube-public"
		pod3.Labels["label"] = "value"
		Expect(fakeClient.Create(ctx, pod3)).To(Succeed())

		pod4 := plainPod.DeepCopy()
		pod4.Name = "bar"
		pod4.Namespace = "kube-node-lease"
		pod4.Labels["compliance.gardener.cloud/role"] = "diki-privileged-pod"
		Expect(fakeClient.Create(ctx, pod4)).To(Succeed())

		options.AcceptedPods[0].PodMatchLabels["label"] = "value"
		options.AcceptedPods[0].Status = "Passed"
		r := &v1r11.Rule242417{
			Client:  fakeClient,
			Options: options,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("System pod in system namespaces.", rule.NewTarget("name", "bar", "namespace", "kube-system", "kind", "pod")),
			rule.PassedCheckResult("System pod in system namespaces.", rule.NewTarget("name", "bar", "namespace", "kube-public", "kind", "pod")),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return failed checkResult when user pods are present in system namespaces", func() {
		pod1 := plainPod.DeepCopy()
		pod1.Name = "foo"
		pod1.Namespace = "kube-system"
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "bar"
		pod2.Namespace = "kube-public"
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		pod3 := plainPod.DeepCopy()
		pod3.Name = "foobar"
		pod3.Namespace = "kube-node-lease"
		pod3.Labels["label"] = "gardener"
		Expect(fakeClient.Create(ctx, pod3)).To(Succeed())

		r := &v1r11.Rule242417{Client: fakeClient}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Found user pods in system namespaces.", rule.NewTarget("name", pod1.Name, "namespace", pod1.Namespace, "kind", "pod")),
			rule.FailedCheckResult("Found user pods in system namespaces.", rule.NewTarget("name", pod2.Name, "namespace", pod2.Namespace, "kind", "pod")),
			rule.FailedCheckResult("Found user pods in system namespaces.", rule.NewTarget("name", pod3.Name, "namespace", pod3.Namespace, "kind", "pod")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct checkResult when different statuses are used", func() {
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Namespace = "kube-system"
		pod1.Labels["foo-bar"] = "bar"
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "bar"
		pod2.Namespace = "kube-system"
		pod2.Labels["foo"] = "bar"
		pod2.Labels["bar"] = "foo"
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		pod3 := plainPod.DeepCopy()
		pod3.Name = "bar"
		pod3.Namespace = "kube-public"
		pod3.Labels["foo"] = "bar"
		Expect(fakeClient.Create(ctx, pod3)).To(Succeed())

		pod4 := plainPod.DeepCopy()
		pod4.Name = "bar"
		pod4.Namespace = "kube-node-lease"
		pod4.Labels["compliance.gardener.cloud/role"] = "diki-privileged-pod"
		Expect(fakeClient.Create(ctx, pod4)).To(Succeed())

		options.AcceptedPods[0].PodMatchLabels["foo"] = "bar"
		options.AcceptedPods[0].PodMatchLabels["bar"] = "foo"
		options.AcceptedPods[0].Status = "Accepted"
		options.AcceptedPods[0].Justification = "Accept pod."
		options.AcceptedPods[0].NamespaceNames = []string{"kube-system"}
		options.AcceptedPods = append(options.AcceptedPods, v1r11.AcceptedPods242417{
			PodMatchLabels: map[string]string{
				"foo": "bar",
			},
			NamespaceNames: []string{"kube-system", "kube-public", "kube-node-lease"},
		})
		options.AcceptedPods = append(options.AcceptedPods, v1r11.AcceptedPods242417{
			PodMatchLabels: map[string]string{
				"foo-bar": "bar",
			},
			NamespaceNames: []string{"kube-system", "kube-public", "kube-node-lease"},
			Status:         "fake",
		})
		r := &v1r11.Rule242417{
			Client:  fakeClient,
			Options: options,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.WarningCheckResult("unrecognized status: fake", rule.NewTarget("name", "pod1", "namespace", "kube-system", "kind", "pod")),
			rule.AcceptedCheckResult("Accept pod.", rule.NewTarget("name", "bar", "namespace", "kube-system", "kind", "pod")),
			rule.AcceptedCheckResult("Accepted user pod in system namespaces.", rule.NewTarget("name", "bar", "namespace", "kube-public", "kind", "pod")),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	Describe("#Validate", func() {
		It("should correctly validate options", func() {
			options = &v1r11.Options242417{
				AcceptedPods: []v1r11.AcceptedPods242417{
					{
						PodMatchLabels: map[string]string{},
						NamespaceNames: []string{"default", "kube-public", "kube-node-lease"},
						Status:         "Passed",
					},
					{
						PodMatchLabels: map[string]string{
							"-foo": "bar",
						},
						NamespaceNames: []string{"kube-system"},
						Status:         "Accepted",
					},
					{
						PodMatchLabels: map[string]string{
							"foo": "?bar",
						},
						NamespaceNames: []string{},
						Status:         "asd",
					},
				},
			}

			result := options.Validate()

			Expect(result).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":     Equal(field.ErrorTypeInvalid),
				"Field":    Equal("acceptedPods.namespaceNames"),
				"BadValue": Equal("default"),
				"Detail":   Equal("must be one of 'kube-system', 'kube-public' or 'kube-node-lease'"),
			})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods.podMatchLabels"),
					"BadValue": Equal("-foo"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods.podMatchLabels"),
					"BadValue": Equal("?bar"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods.status"),
					"BadValue": Equal("asd"),
					"Detail":   Equal("must be one of 'Passed' or 'Accepted'"),
				})),
			))
		})
	})
})
