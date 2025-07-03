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

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#242417", func() {
	var (
		fakeClient     client.Client
		plainPod       *corev1.Pod
		plainNamespace *corev1.Namespace
		options        *rules.Options242417
		ctx            = context.TODO()
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		plainPod = &corev1.Pod{
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
		options = &rules.Options242417{
			AcceptedPods: []rules.AcceptedPods242417{
				{
					PodSelector: option.PodSelector{
						PodMatchLabels:       map[string]string{},
						NamespaceMatchLabels: map[string]string{"random1": "value1"},
					},
				},
				{
					PodSelector: option.PodSelector{
						PodMatchLabels:       map[string]string{},
						NamespaceMatchLabels: map[string]string{"random2": "value2"},
					},
				},
			},
		}
		kubeNodeLeaseNamespace := plainNamespace.DeepCopy()
		kubeNodeLeaseNamespace.Name = "kube-node-lease"
		kubeNodeLeaseNamespace.Labels["random1"] = "value1"

		kubeSystemNamespace := plainNamespace.DeepCopy()
		kubeSystemNamespace.Name = "kube-system"
		kubeSystemNamespace.Labels["random1"] = "value1"

		kubePublicNamespace := plainNamespace.DeepCopy()
		kubePublicNamespace.Name = "kube-public"
		kubePublicNamespace.Labels["random2"] = "value2"

		Expect(fakeClient.Create(ctx, kubeNodeLeaseNamespace)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubePublicNamespace)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubeSystemNamespace)).To(Succeed())

	})

	It("should return passed checkResult when no pods are present in system namespaces", func() {
		r := &rules.Rule242417{
			Client:  fakeClient,
			Options: options,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("The cluster does not have any pods for evaluation.", rule.NewTarget()),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
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
		pod4.Labels["i_am"] = "privileged"
		pod4.Labels["compliance.gardener.cloud/role"] = "diki-privileged-pod"
		Expect(fakeClient.Create(ctx, pod4)).To(Succeed())

		options.AcceptedPods[0].PodMatchLabels["label"] = "value"
		options.AcceptedPods[0].Status = "Passed"
		options.AcceptedPods[1].PodMatchLabels["label"] = "value"
		options.AcceptedPods[1].Status = "Passed"

		r := &rules.Rule242417{
			Client:  fakeClient,
			Options: options,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("System pod in system namespaces.", rule.NewTarget("name", "bar", "namespace", "kube-system", "kind", "Pod")),
			rule.PassedCheckResult("System pod in system namespaces.", rule.NewTarget("name", "bar", "namespace", "kube-public", "kind", "Pod")),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return correct targets when pods have owner references", func() {
		deployment := &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{
				Kind: "Deployment",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment",
				Namespace: "kube-system",
				UID:       "1",
			},
		}
		Expect(fakeClient.Create(ctx, deployment)).To(Succeed())

		replicaSet := &appsv1.ReplicaSet{
			TypeMeta: metav1.TypeMeta{
				Kind: "ReplicaSet",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "replicaSet",
				Namespace: "kube-system",
				UID:       "3",
				OwnerReferences: []metav1.OwnerReference{
					{
						UID:  "1",
						Name: "deployment",
						Kind: "Deployment",
					},
				},
			},
		}
		Expect(fakeClient.Create(ctx, replicaSet)).To(Succeed())

		daemonSet := &appsv1.DaemonSet{
			TypeMeta: metav1.TypeMeta{
				Kind: "DaemonSet",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "daemonSet",
				Namespace: "kube-public",
				UID:       "2",
			},
		}
		Expect(fakeClient.Create(ctx, daemonSet)).To(Succeed())

		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "bar"
		pod2.Namespace = "kube-system"
		pod2.Labels["label"] = "value"
		pod2.OwnerReferences = []metav1.OwnerReference{
			{
				UID:        "3",
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "replicaSet",
			},
		}
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		pod3 := plainPod.DeepCopy()
		pod3.Name = "bar"
		pod3.Namespace = "kube-public"
		pod3.Labels["label"] = "value"
		pod3.OwnerReferences = []metav1.OwnerReference{
			{
				UID:  "2",
				Kind: "DaemonSet",
				Name: "daemonSet",
			},
		}
		Expect(fakeClient.Create(ctx, pod3)).To(Succeed())

		pod4 := plainPod.DeepCopy()
		pod4.Name = "bar"
		pod4.Namespace = "kube-node-lease"
		pod4.Labels["i_am"] = "privileged"
		pod4.Labels["compliance.gardener.cloud/role"] = "diki-privileged-pod"
		Expect(fakeClient.Create(ctx, pod4)).To(Succeed())

		options.AcceptedPods[0].PodMatchLabels["label"] = "value"
		options.AcceptedPods[0].Status = "Passed"
		options.AcceptedPods[1].PodMatchLabels["label"] = "value"
		options.AcceptedPods[1].Status = "Passed"

		r := &rules.Rule242417{
			Client:  fakeClient,
			Options: options,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("System pod in system namespaces.", rule.NewTarget("name", "deployment", "namespace", "kube-system", "kind", "Deployment")),
			rule.PassedCheckResult("System pod in system namespaces.", rule.NewTarget("name", "daemonSet", "namespace", "kube-public", "kind", "DaemonSet")),
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

		options.AcceptedPods[0].PodMatchLabels["label"] = "value"
		options.AcceptedPods[0].Status = "Passed"

		r := &rules.Rule242417{Client: fakeClient,
			Options: options}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Found user pods in system namespaces.", rule.NewTarget("name", pod1.Name, "namespace", pod1.Namespace, "kind", "Pod")),
			rule.FailedCheckResult("Found user pods in system namespaces.", rule.NewTarget("name", pod2.Name, "namespace", pod2.Namespace, "kind", "Pod")),
			rule.FailedCheckResult("Found user pods in system namespaces.", rule.NewTarget("name", pod3.Name, "namespace", pod3.Namespace, "kind", "Pod")),
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
		pod2.Name = "pod2"
		pod2.Namespace = "kube-system"
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

		options.AcceptedPods[0].PodMatchLabels["foo"] = "bar"
		options.AcceptedPods[0].PodMatchLabels["bar"] = "foo"
		options.AcceptedPods[0].Status = "Accepted"
		options.AcceptedPods[0].Justification = "Accept pod."

		options.AcceptedPods = append(options.AcceptedPods, rules.AcceptedPods242417{
			PodSelector: option.PodSelector{
				PodMatchLabels:       map[string]string{"foo": "bar"},
				NamespaceMatchLabels: map[string]string{"functionality": "system"},
			},
		})

		options.AcceptedPods = append(options.AcceptedPods, rules.AcceptedPods242417{
			PodSelector: option.PodSelector{
				PodMatchLabels:       map[string]string{"foo-bar": "bar"},
				NamespaceMatchLabels: map[string]string{"functionality": "system"},
			},
			Status: "fake",
		})

		r := &rules.Rule242417{
			Client:  fakeClient,
			Options: options,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.WarningCheckResult("unrecognized status: fake", rule.NewTarget("name", "pod1", "namespace", "kube-system", "kind", "Pod")),
			rule.AcceptedCheckResult("Accept pod.", rule.NewTarget("name", "pod2", "namespace", "kube-system", "kind", "Pod")),
			rule.AcceptedCheckResult("Accepted user pod in system namespaces.", rule.NewTarget("name", "pod3", "namespace", "kube-public", "kind", "Pod")),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	Describe("#Validate", func() {
		It("should correctly validate options", func() {
			options = &rules.Options242417{
				AcceptedPods: []rules.AcceptedPods242417{
					{
						PodSelector: option.PodSelector{
							PodMatchLabels:       map[string]string{"typeOfPod": "veryImportant"},
							NamespaceMatchLabels: map[string]string{"namespaceType": "system"},
						},
						Status: "Passed",
					},
					{
						PodSelector: option.PodSelector{
							PodMatchLabels:       map[string]string{"typeOfPod": "veryImportant"},
							NamespaceMatchLabels: map[string]string{"namespaceType": "system"},
						},
						Status: "Accepted",
					},
					{
						PodSelector: option.PodSelector{
							PodMatchLabels:       map[string]string{"typeOfPod": "veryImportant"},
							NamespaceMatchLabels: map[string]string{"namespaceType": "system"},
						},
						Status: "fake",
					},
					{
						PodSelector: option.PodSelector{
							PodMatchLabels:       map[string]string{"typeOfPod": "veryImportant"},
							NamespaceMatchLabels: map[string]string{"namespaceType": "system"},
						},
					},
				},
			}

			result := options.Validate()

			Expect(result).To(ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":     Equal(field.ErrorTypeInvalid),
				"Field":    Equal("acceptedPods.status"),
				"BadValue": Equal("fake"),
				"Detail":   Equal("must be one of 'Passed' or 'Accepted'"),
			})),
			))
		})
	})
})
