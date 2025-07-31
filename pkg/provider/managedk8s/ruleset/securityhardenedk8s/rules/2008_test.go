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
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var _ = Describe("#2008", func() {
	var (
		client        client.Client
		options       rules.Options2008
		plainPod      *corev1.Pod
		ctx           = context.TODO()
		namespaceName = "foo"
		namespace     *corev1.Namespace
	)

	BeforeEach(func() {
		client = fakeclient.NewClientBuilder().Build()
		namespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
		}
		plainPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "test",
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "test",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: "test",
							},
						},
					},
				},
			},
		}
	})

	It("should pass when no pods are deployed", func() {
		r := &rules.Rule2008{Client: client, Options: &options}
		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("The cluster does not have any Pods.", rule.NewTarget()),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when all pods pass", func() {
		r := &rules.Rule2008{Client: client, Options: &options}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		Expect(client.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not use volumes of type hostPath.",
				Target:  rule.NewTarget("name", "pod1", "namespace", "foo", "kind", "Pod"),
			},
			{
				Status:  rule.Passed,
				Message: "Pod does not use volumes of type hostPath.",
				Target:  rule.NewTarget("name", "pod2", "namespace", "foo", "kind", "Pod"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when a pod fails", func() {
		r := &rules.Rule2008{Client: client, Options: &options}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		Expect(client.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.Spec.Volumes = append(pod2.Spec.Volumes, corev1.Volume{
			Name: "foo",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "foo/bar",
				},
			},
		})
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not use volumes of type hostPath.",
				Target:  rule.NewTarget("name", "pod1", "namespace", "foo", "kind", "Pod"),
			},
			{
				Status:  rule.Failed,
				Message: "Pod must not use volumes of type hostPath.",
				Target:  rule.NewTarget("name", "pod2", "namespace", "foo", "kind", "Pod", "volume", "foo"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when checking diki privileged pod", func() {
		r := &rules.Rule2008{Client: client, Options: &options}
		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		Expect(client.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "diki-privileged-pod"
		pod2.Labels = map[string]string{
			"compliance.gardener.cloud/role": "diki-privileged-pod",
		}
		pod2.Spec.Volumes = append(pod2.Spec.Volumes, corev1.Volume{
			Name: "foo",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "foo/bar",
				},
			},
		})
		Expect(client.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not use volumes of type hostPath.",
				Target:  rule.NewTarget("name", "pod1", "namespace", "foo", "kind", "Pod"),
			},
			{
				Status:  rule.Skipped,
				Message: "Diki privileged pod requires the use of hostPaths.",
				Target:  rule.NewTarget("name", "diki-privileged-pod", "namespace", "foo", "kind", "Pod"),
			},
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return correct results when options are present", func() {
		options = rules.Options2008{
			AcceptedPods: []rules.AcceptedPods2008{
				{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						MatchLabels:          map[string]string{"foo": "bar"},
						NamespaceMatchLabels: map[string]string{"foo": "not-bar"},
					},
					VolumeNames: []string{"bar"},
				},
				{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						MatchLabels:          map[string]string{"foo": "bar"},
						NamespaceMatchLabels: map[string]string{"foo": "bar"},
					},
					Justification: "foo justify",
					VolumeNames:   []string{"foo"},
				},
			},
		}

		r := &rules.Rule2008{Client: client, Options: &options}

		acceptedShootPod := plainPod.DeepCopy()
		acceptedShootPod.Name = "accepted-shoot-pod"
		acceptedShootPod.Spec.Volumes = append(acceptedShootPod.Spec.Volumes, corev1.Volume{
			Name: "foo",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "foo/bar",
				},
			},
		})

		notAcceptedShootPod := plainPod.DeepCopy()
		notAcceptedShootPod.Name = "not-accepted-shoot-pod"
		notAcceptedShootPod.Spec.Volumes = append(notAcceptedShootPod.Spec.Volumes, corev1.Volume{
			Name: "bar",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "foo/bar",
				},
			},
		})

		Expect(client.Create(ctx, namespace)).To(Succeed())
		Expect(client.Create(ctx, acceptedShootPod)).To(Succeed())
		Expect(client.Create(ctx, notAcceptedShootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Accepted,
				Message: "foo justify",
				Target:  rule.NewTarget("name", "accepted-shoot-pod", "namespace", "foo", "kind", "Pod", "volume", "foo"),
			},
			{
				Status:  rule.Failed,
				Message: "Pod must not use volumes of type hostPath.",
				Target:  rule.NewTarget("name", "not-accepted-shoot-pod", "namespace", "foo", "kind", "Pod", "volume", "bar"),
			},
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should accept all volumes when a wildcard accepted pod is matched", func() {
		options := &rules.Options2008{
			AcceptedPods: []rules.AcceptedPods2008{
				{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						NamespaceMatchLabels: map[string]string{
							"namespace": "foo",
						},
						MatchLabels: map[string]string{
							"pod": "bar",
						},
					},
					Justification: "accepted wildcard",
					VolumeNames:   []string{"*"},
				},
			},
		}

		r := &rules.Rule2008{Client: client, Options: options}

		labeledNamespace := &corev1.Namespace{}
		labeledNamespace.Name = "labeledNamespace"
		labeledNamespace.Labels = map[string]string{
			"namespace": "foo",
		}
		Expect(client.Create(ctx, labeledNamespace)).To(Succeed())

		labeledNamespacePod := plainPod.DeepCopy()
		labeledNamespacePod.Name = "labeledNamespacePod"
		labeledNamespacePod.Labels = map[string]string{"pod": "bar"}
		labeledNamespacePod.Namespace = labeledNamespace.Name
		labeledNamespacePod.Spec.Volumes = []corev1.Volume{
			{
				Name: "volume1",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{},
				},
			},
			{
				Name: "volume2",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{},
				},
			},
			{
				Name: "volume3",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{},
				},
			},
			{
				Name: "permittedVolume",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{},
				},
			},
		}
		Expect(client.Create(ctx, labeledNamespacePod)).To(Succeed())

		result, err := r.Run(ctx)
		Expect(err).To(BeNil())

		Expect(result.CheckResults).To(Equal([]rule.CheckResult{
			{Status: rule.Accepted, Message: "accepted wildcard", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "volume1")},
			{Status: rule.Accepted, Message: "accepted wildcard", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "volume2")},
			{Status: rule.Accepted, Message: "accepted wildcard", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "volume3")},
		}))
	})

	It("should return correct targets when pods have owner references", func() {
		r := &rules.Rule2008{Client: client, Options: &rules.Options2008{}}

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

		pod1 := plainPod.DeepCopy()
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

		pod2 := plainPod.DeepCopy()
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
				{Status: rule.Passed, Message: "Pod does not use volumes of type hostPath.", Target: rule.NewTarget("kind", "Deployment", "name", "foo", "namespace", "foo")},
				{Status: rule.Passed, Message: "Pod does not use volumes of type hostPath.", Target: rule.NewTarget("kind", "DaemonSet", "name", "bar", "namespace", "foo")},
			},
		))
	})

	Describe("#ValidateOptions2008", func() {
		It("should correctly validate options", func() {
			options := rules.Options2008{
				AcceptedPods: []rules.AcceptedPods2008{
					{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
							NamespaceMatchLabels: map[string]string{
								"foo": "bar",
							},
						},
					},
					{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
							NamespaceMatchLabels: map[string]string{
								"foo": "bar",
							},
						},
						VolumeNames: []string{"foo"},
					},
					{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
							NamespaceMatchLabels: map[string]string{
								"foo": "bar",
							},
						},
						VolumeNames: []string{""},
					},
				},
			}

			result := options.Validate(field.NewPath("foo"))

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("foo.acceptedPods[0].volumeNames"),
					"Detail": Equal("must not be empty"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("foo.acceptedPods[2].volumeNames[0]"),
					"BadValue": Equal(""),
					"Detail":   Equal("must not be empty"),
				})),
			))
		})
	})
})
