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
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#242383", func() {
	var (
		fakeClient     client.Client
		plainPod       *corev1.Pod
		options        *rules.Options242383
		ctx            = context.TODO()
		plainNamespace *corev1.Namespace
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		plainPod = &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Pod",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "foo",
				Labels:    map[string]string{},
			},
		}
		plainNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "",
				Labels: map[string]string{"functionality": "system"},
			},
		}
		options = &rules.Options242383{
			AcceptedResources: []rules.AcceptedResources242383{
				{
					ObjectSelector: rules.ObjectSelector{
						APIVersion:           "v1",
						Kind:                 "Pod",
						MatchLabels:          map[string]string{},
						NamespaceMatchLabels: map[string]string{"random_1": "value_1"},
					},
				},
				{
					ObjectSelector: rules.ObjectSelector{
						APIVersion:           "v1",
						Kind:                 "Pod",
						MatchLabels:          map[string]string{},
						NamespaceMatchLabels: map[string]string{"random_2": "value_2"},
					},
				},
			},
		}

		defaultNamespace := plainNamespace.DeepCopy()
		defaultNamespace.Name = "default"
		defaultNamespace.Labels["random_1"] = "value_1"
		defaultNamespace.Labels["kubernetes.io/metadata.name"] = "default"

		kubeNodeLeaseNamespace := plainNamespace.DeepCopy()
		kubeNodeLeaseNamespace.Name = "kude-node-lease"
		kubeNodeLeaseNamespace.Labels["random_2"] = "value_2"
		kubeNodeLeaseNamespace.Labels["kubernetes.io/metadata.name"] = "kube-node-lease"

		kubePublicNamespace := plainNamespace.DeepCopy()
		kubePublicNamespace.Name = "kube-public"
		kubePublicNamespace.Labels["random_2"] = "value_2"
		kubePublicNamespace.Labels["kubernetes.io/metadata.name"] = "kube-public"

		Expect(fakeClient.Create(ctx, defaultNamespace)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubeNodeLeaseNamespace)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubePublicNamespace)).To(Succeed())
	})

	It("should return passed checkResult when no user resources are present in system namespaces", func() {
		kubernetesService := &corev1.Service{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Service",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kubernetes",
				Namespace: "default",
				Labels: map[string]string{
					"component": "apiserver",
					"provider":  "kubernetes",
				},
			},
		}

		Expect(fakeClient.Create(ctx, kubernetesService)).To(Succeed())

		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Namespace = "default"
		pod2.Labels["label"] = "value"
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		pod3 := plainPod.DeepCopy()
		pod3.Name = "pod3"
		pod3.Namespace = "kube-public"
		pod3.Labels["label"] = "value"
		Expect(fakeClient.Create(ctx, pod3)).To(Succeed())

		pod4 := plainPod.DeepCopy()
		pod4.Name = "pod4"
		pod4.Namespace = "kube-node-lease"
		pod4.Labels["compliance.gardener.cloud/role"] = "diki-privileged-pod"
		Expect(fakeClient.Create(ctx, pod4)).To(Succeed())

		options.AcceptedResources[0].MatchLabels["label"] = "value"
		options.AcceptedResources[0].Status = "Passed"
		options.AcceptedResources[1].MatchLabels["label"] = "value"
		options.AcceptedResources[1].Status = "Passed"
		r := &rules.Rule242383{
			Client:  fakeClient,
			Options: options,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("System resource in system namespaces.", rule.NewTarget("name", "kubernetes", "namespace", "default", "kind", "Service")),
			rule.PassedCheckResult("System resource in system namespaces.", rule.NewTarget("name", "pod2", "namespace", "default", "kind", "Pod")),
			rule.PassedCheckResult("System resource in system namespaces.", rule.NewTarget("name", "pod3", "namespace", "kube-public", "kind", "Pod")),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return failed checkResult when user resources are present in system namespaces", func() {
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Namespace = "default"
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Namespace = "kube-public"
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		pod3 := plainPod.DeepCopy()
		pod3.Name = "pod3"
		pod3.Namespace = "kube-node-lease"
		pod3.Labels["label"] = "gardener"
		Expect(fakeClient.Create(ctx, pod3)).To(Succeed())

		r := &rules.Rule242383{Client: fakeClient}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Found user resource in system namespaces.", rule.NewTarget("name", pod1.Name, "namespace", pod1.Namespace, "kind", "Pod")),
			rule.FailedCheckResult("Found user resource in system namespaces.", rule.NewTarget("name", pod2.Name, "namespace", pod2.Namespace, "kind", "Pod")),
			rule.FailedCheckResult("Found user resource in system namespaces.", rule.NewTarget("name", pod3.Name, "namespace", pod3.Namespace, "kind", "Pod")),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return correct checkResult when different resources are present", func() {
		pod := plainPod.DeepCopy()
		pod.Name = "foo"
		pod.Namespace = "default"
		Expect(fakeClient.Create(ctx, pod)).To(Succeed())

		deployment := &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{
				Kind: "Deployment",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment",
				Namespace: "default",
			},
		}
		Expect(fakeClient.Create(ctx, deployment)).To(Succeed())

		daemonSet := &appsv1.DaemonSet{
			TypeMeta: metav1.TypeMeta{
				Kind: "DaemonSet",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "daemonSet",
				Namespace: "kube-public",
			},
		}
		Expect(fakeClient.Create(ctx, daemonSet)).To(Succeed())

		job := &batchv1.Job{
			TypeMeta: metav1.TypeMeta{
				Kind: "Job",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "job",
				Namespace: "kube-node-lease",
			},
		}
		Expect(fakeClient.Create(ctx, job)).To(Succeed())

		r := &rules.Rule242383{Client: fakeClient}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Found user resource in system namespaces.", rule.NewTarget("name", pod.Name, "namespace", pod.Namespace, "kind", pod.Kind)),
			rule.FailedCheckResult("Found user resource in system namespaces.", rule.NewTarget("name", deployment.Name, "namespace", deployment.Namespace, "kind", deployment.Kind)),
			rule.FailedCheckResult("Found user resource in system namespaces.", rule.NewTarget("name", daemonSet.Name, "namespace", daemonSet.Namespace, "kind", daemonSet.Kind)),
			rule.FailedCheckResult("Found user resource in system namespaces.", rule.NewTarget("name", job.Name, "namespace", job.Namespace, "kind", job.Kind)),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return correct checkResult when different statuses are used", func() {
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Namespace = "default"
		pod1.Labels["foo-bar"] = "bar"
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Namespace = "default"
		pod2.Labels["foo"] = "bar"
		pod2.Labels["bar"] = "foo"
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		pod3 := plainPod.DeepCopy()
		pod3.Name = "pod3"
		pod3.Namespace = "kube-public"
		pod3.Labels["foo"] = "bar"
		Expect(fakeClient.Create(ctx, pod3)).To(Succeed())

		pod4 := plainPod.DeepCopy()
		pod4.Name = "pod4"
		pod4.Namespace = "kube-node-lease"
		pod4.Labels["compliance.gardener.cloud/role"] = "diki-privileged-pod"
		Expect(fakeClient.Create(ctx, pod4)).To(Succeed())

		options.AcceptedResources[0].MatchLabels["foo"] = "bar"
		options.AcceptedResources[0].MatchLabels["bar"] = "foo"
		options.AcceptedResources[0].Status = "Accepted"
		options.AcceptedResources[0].Justification = "Accept pod."

		options.AcceptedResources[1].MatchLabels["foo"] = "bar"
		options.AcceptedResources[1].MatchLabels["bar"] = "foo"
		options.AcceptedResources[1].Status = "Accepted"
		options.AcceptedResources[1].Justification = "Accept pod."

		options.AcceptedResources = append(options.AcceptedResources, rules.AcceptedResources242383{
			ObjectSelector: rules.ObjectSelector{
				APIVersion:           "v1",
				Kind:                 "*",
				MatchLabels:          map[string]string{"foo": "bar"},
				NamespaceMatchLabels: map[string]string{"random_2": "value_2"},
			},
		})
		options.AcceptedResources = append(options.AcceptedResources, rules.AcceptedResources242383{
			ObjectSelector: rules.ObjectSelector{
				APIVersion:           "v1",
				Kind:                 "*",
				MatchLabels:          map[string]string{"foo-bar": "bar"},
				NamespaceMatchLabels: map[string]string{"random_1": "value_1"},
			},
			Status: "fake",
		})

		r := &rules.Rule242383{
			Client:  fakeClient,
			Options: options,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.WarningCheckResult("unrecognized status: fake", rule.NewTarget("name", "pod1", "namespace", "default", "kind", "Pod")),
			rule.AcceptedCheckResult("Accept pod.", rule.NewTarget("name", "pod2", "namespace", "default", "kind", "Pod")),
			rule.AcceptedCheckResult("Accepted user resource in system namespaces.", rule.NewTarget("name", "pod3", "namespace", "kube-public", "kind", "Pod")),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	Describe("#Validate", func() {
		It("should correctly validate options", func() {
			options = &rules.Options242383{
				AcceptedResources: []rules.AcceptedResources242383{
					{
						ObjectSelector: rules.ObjectSelector{
							APIVersion:           "v1",
							Kind:                 "Pod",
							MatchLabels:          map[string]string{"bar": "foo"},
							NamespaceMatchLabels: map[string]string{"foo": "bar"},
						},
						Status: "Passed",
					},
					{
						ObjectSelector: rules.ObjectSelector{
							APIVersion:           "apps/v1",
							Kind:                 "Service",
							MatchLabels:          map[string]string{"bar": "foo"},
							NamespaceMatchLabels: map[string]string{"foo": "bar"},
						},
						Status: "Passed",
					},
					{
						ObjectSelector: rules.ObjectSelector{
							APIVersion:           "v1",
							Kind:                 "Deployment",
							MatchLabels:          map[string]string{"-foo": "bar"},
							NamespaceMatchLabels: map[string]string{},
						},
						Status: "Accepted",
					},
					{
						ObjectSelector: rules.ObjectSelector{
							APIVersion:           "v1",
							Kind:                 "Service",
							MatchLabels:          map[string]string{},
							NamespaceMatchLabels: map[string]string{"foo": "bar"},
						},
						Status: "Accepted",
					},
					{
						ObjectSelector: rules.ObjectSelector{
							APIVersion:           "fake",
							Kind:                 "Service",
							MatchLabels:          map[string]string{"foo": "?bar"},
							NamespaceMatchLabels: map[string]string{"ba$r": "_foo"},
						},
						Status: "asd",
					},
				},
			}

			result := options.Validate()

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedResources.kind"),
					"BadValue": Equal("Deployment"),
					"Detail":   Equal("not checked kind for apiVerion v1"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedResources.kind"),
					"BadValue": Equal("Service"),
					"Detail":   Equal("not checked kind for apiVerion apps/v1"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("acceptedResources.namespaceMatchLabels"),
					"Detail": Equal("must not be empty"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("acceptedResources.matchLabels"),
					"Detail": Equal("must not be empty"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedResources.matchLabels"),
					"BadValue": Equal("-foo"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedResources.apiVersion"),
					"BadValue": Equal("fake"),
					"Detail":   Equal("not checked apiVersion"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedResources.matchLabels"),
					"BadValue": Equal("?bar"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedResources.namespaceMatchLabels"),
					"BadValue": Equal("ba$r"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedResources.namespaceMatchLabels"),
					"BadValue": Equal("_foo"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedResources.status"),
					"BadValue": Equal("asd"),
					"Detail":   Equal("must be one of 'Passed' or 'Accepted'"),
				})),
			))
		})
	})
})
