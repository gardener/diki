// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
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

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var _ = Describe("#2003", func() {

	var (
		fakeClient    client.Client
		plainPod      *corev1.Pod
		ctx           = context.TODO()
		namespaceName = "plainNamespace"
		namespace     *corev1.Namespace
		r             rules.Rule2003
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
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
		}
	})

	DescribeTable("Run cases", func(updatePodConfig func(), ruleOptions *rules.Options2003, expectedCheckResults []rule.CheckResult) {
		Expect(fakeClient.Create(ctx, namespace)).To(Succeed())

		updatePodConfig()

		r = rules.Rule2003{Client: fakeClient, Options: ruleOptions}
		result, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(result.CheckResults).To(Equal(expectedCheckResults))
	},
		Entry("should pass when no pods are present in the target",
			func() {
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "The cluster does not have any Pods.", Target: rule.NewTarget()},
			},
		),
		Entry("should pass when all pod volumes are of an allowed type",
			func() {
				podWithPermittedVolumes := plainPod.DeepCopy()
				podWithPermittedVolumes.Name = "podWithPermittedVolumes"
				podWithPermittedVolumes.Spec.Volumes = []corev1.Volume{
					{
						Name: "configMapVolume",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{},
						},
					},
					{
						Name: "emptyDirVolume",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
					{
						Name: "projectedVolume",
						VolumeSource: corev1.VolumeSource{
							Projected: &corev1.ProjectedVolumeSource{},
						},
					},
				}
				Expect(fakeClient.Create(ctx, podWithPermittedVolumes)).To(Succeed())
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Pod uses only allowed volume types.", Target: rule.NewTarget("kind", "Pod", "name", "podWithPermittedVolumes", "namespace", "plainNamespace")},
			},
		),
		Entry("should fail when a pod volume is not of an allowed type",
			func() {
				podWithNotPermittedVolumes := plainPod.DeepCopy()
				podWithNotPermittedVolumes.Name = "podWithNotPermittedVolumes"
				podWithNotPermittedVolumes.Spec.Volumes = []corev1.Volume{
					{
						Name: "emptyDirVolume",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
					{
						Name: "cinderVolume",
						VolumeSource: corev1.VolumeSource{
							Cinder: &corev1.CinderVolumeSource{},
						},
					},
				}
				Expect(fakeClient.Create(ctx, podWithNotPermittedVolumes)).To(Succeed())
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "Pod uses not allowed volume type.", Target: rule.NewTarget("kind", "Pod", "name", "podWithNotPermittedVolumes", "namespace", "plainNamespace", "volume", "cinderVolume")},
			},
		),
		Entry("should skip when a pod is a diki privileged pod",
			func() {
				dikiPrivilegedPod := plainPod.DeepCopy()
				dikiPrivilegedPod.Name = "dikiPrivilegedPod"
				dikiPrivilegedPod.Labels = map[string]string{
					"compliance.gardener.cloud/role": "diki-privileged-pod",
				}
				dikiPrivilegedPod.Spec.Volumes = []corev1.Volume{
					{
						Name: "emptyDirVolume",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
					{
						Name: "cinderVolume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "foo/bar",
							},
						},
					},
				}
				Expect(fakeClient.Create(ctx, dikiPrivilegedPod)).To(Succeed())
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Skipped, Message: "Diki privileged pod requires the use of hostPaths.", Target: rule.NewTarget("kind", "Pod", "name", "dikiPrivilegedPod", "namespace", "plainNamespace")},
			},
		),
		Entry("should accept a volume when it is specified in the options configuration",
			func() {

				acceptedPod := plainPod.DeepCopy()
				acceptedPod.Name = "acceptedPod"
				acceptedPod.Labels = map[string]string{"podFoo": "podBar"}
				acceptedPod.Namespace = namespaceName
				acceptedPod.Spec.Volumes = []corev1.Volume{
					{
						Name: "acceptedVolume1",
						VolumeSource: corev1.VolumeSource{
							Cinder: &corev1.CinderVolumeSource{},
						},
					},
					{
						Name: "permittedVolume1",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{},
						},
					},
				}
				Expect(fakeClient.Create(ctx, acceptedPod)).To(Succeed())
			},
			&rules.Options2003{
				AcceptedPods: []option.AcceptedPodVolumes{
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"podFoo": "podBar",
									},
								},
								NamespaceLabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foo": "bar",
									},
								},
							},
							Justification: "justification 1",
						},
						VolumeNames: []string{"acceptedVolume1"},
					},
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{},
						VolumeNames:              []string{"acceptedVolume1"},
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Accepted, Message: "justification 1", Target: rule.NewTarget("kind", "Pod", "name", "acceptedPod", "namespace", "plainNamespace", "volume", "acceptedVolume1")},
			},
		),
		Entry("should return appropriate check results for multiple pods",
			func() {

				acceptedPod := plainPod.DeepCopy()
				acceptedPod.Name = "acceptedPod"
				acceptedPod.Labels = map[string]string{"podFoo": "podBar"}
				acceptedPod.Namespace = namespaceName
				acceptedPod.Spec.Volumes = []corev1.Volume{
					{
						Name: "acceptedVolume1",
						VolumeSource: corev1.VolumeSource{
							Cinder: &corev1.CinderVolumeSource{},
						},
					},
					{
						Name: "permittedVolume1",
						VolumeSource: corev1.VolumeSource{
							Projected: &corev1.ProjectedVolumeSource{},
						},
					},
					{
						Name: "permittedVolume2",
						VolumeSource: corev1.VolumeSource{
							Ephemeral: &corev1.EphemeralVolumeSource{},
						},
					},
					{
						Name: "forbiddenVolume1",
						VolumeSource: corev1.VolumeSource{
							CephFS: &corev1.CephFSVolumeSource{},
						},
					},
				}

				Expect(fakeClient.Create(ctx, acceptedPod)).To(Succeed())

				regularPod := plainPod.DeepCopy()
				regularPod.Name = "regularPod"
				regularPod.Namespace = namespaceName
				regularPod.Spec.Volumes = []corev1.Volume{
					{
						Name: "acceptedVolume1",
						VolumeSource: corev1.VolumeSource{
							Cinder: &corev1.CinderVolumeSource{},
						},
					},
					{
						Name: "permittedVolume1",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{},
						},
					},
					{
						Name: "forbiddenVolume1",
						VolumeSource: corev1.VolumeSource{
							Cinder: &corev1.CinderVolumeSource{},
						},
					},
				}

				Expect(fakeClient.Create(ctx, regularPod)).To(Succeed())
			},
			&rules.Options2003{
				AcceptedPods: []option.AcceptedPodVolumes{
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"podFoo": "podBar",
									},
								},
								NamespaceLabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foo": "bar",
									},
								},
							},
							Justification: "justification 1",
						},
						VolumeNames: []string{"acceptedVolume1"},
					},
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{},
						VolumeNames:              []string{"acceptedVolume1"},
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Accepted, Message: "justification 1", Target: rule.NewTarget("kind", "Pod", "name", "acceptedPod", "namespace", "plainNamespace", "volume", "acceptedVolume1")},
				{Status: rule.Failed, Message: "Pod uses not allowed volume type.", Target: rule.NewTarget("kind", "Pod", "name", "acceptedPod", "namespace", "plainNamespace", "volume", "forbiddenVolume1")},
				{Status: rule.Failed, Message: "Pod uses not allowed volume type.", Target: rule.NewTarget("kind", "Pod", "name", "regularPod", "namespace", "plainNamespace", "volume", "acceptedVolume1")},
				{Status: rule.Failed, Message: "Pod uses not allowed volume type.", Target: rule.NewTarget("kind", "Pod", "name", "regularPod", "namespace", "plainNamespace", "volume", "forbiddenVolume1")},
			},
		),

		Entry("should return appropriate check results for pods in multiple namespaces",
			func() {
				labeledNamespace := &corev1.Namespace{}
				labeledNamespace.Name = "labeledNamespace"
				labeledNamespace.Labels = map[string]string{
					"label": "baz",
				}
				Expect(fakeClient.Create(ctx, labeledNamespace)).To(Succeed())

				labeledNamespacePod := plainPod.DeepCopy()
				labeledNamespacePod.Name = "labeledNamespacePod"
				labeledNamespacePod.Labels = map[string]string{"podFoo": "podBar"}
				labeledNamespacePod.Namespace = labeledNamespace.Name
				labeledNamespacePod.Spec.Volumes = []corev1.Volume{
					{
						Name: "acceptedVolume1",
						VolumeSource: corev1.VolumeSource{
							Cinder: &corev1.CinderVolumeSource{},
						},
					},
				}
				Expect(fakeClient.Create(ctx, labeledNamespacePod)).To(Succeed())

				plainNamespacePod := plainPod.DeepCopy()
				plainNamespacePod.Name = "plainNamespacePod"
				plainNamespacePod.Labels = map[string]string{"podFoo": "podBar"}
				plainNamespacePod.Namespace = namespaceName
				plainNamespacePod.Spec.Volumes = []corev1.Volume{
					{
						Name: "forbiddenVolume1",
						VolumeSource: corev1.VolumeSource{
							Cinder: &corev1.CinderVolumeSource{},
						},
					},
				}
				Expect(fakeClient.Create(ctx, plainNamespacePod)).To(Succeed())
			},
			&rules.Options2003{
				AcceptedPods: []option.AcceptedPodVolumes{
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"podFoo": "podBar",
									},
								},
								NamespaceLabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"label": "baz",
									},
								},
							},
							Justification: "justification 1",
						},
						VolumeNames: []string{"acceptedVolume1"},
					},
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{},
						VolumeNames:              []string{"acceptedVolume1"},
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Accepted, Message: "justification 1", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "acceptedVolume1")},
				{Status: rule.Failed, Message: "Pod uses not allowed volume type.", Target: rule.NewTarget("kind", "Pod", "name", "plainNamespacePod", "namespace", "plainNamespace", "volume", "forbiddenVolume1")},
			},
		),
		Entry("should accept all volume when a wildcard accepted pod is matched", func() {
			labeledNamespace := &corev1.Namespace{}
			labeledNamespace.Name = "labeledNamespace"
			labeledNamespace.Labels = map[string]string{
				"namespace": "foo",
			}
			Expect(fakeClient.Create(ctx, labeledNamespace)).To(Succeed())

			labeledNamespacePod := plainPod.DeepCopy()
			labeledNamespacePod.Name = "labeledNamespacePod"
			labeledNamespacePod.Labels = map[string]string{"pod": "bar"}
			labeledNamespacePod.Namespace = labeledNamespace.Name
			labeledNamespacePod.Spec.Volumes = []corev1.Volume{
				{
					Name: "volume-1",
					VolumeSource: corev1.VolumeSource{
						Cinder: &corev1.CinderVolumeSource{},
					},
				},
				{
					Name: "volume-2",
					VolumeSource: corev1.VolumeSource{
						StorageOS: &corev1.StorageOSVolumeSource{},
					},
				},
				{
					Name: "volume-3",
					VolumeSource: corev1.VolumeSource{
						AWSElasticBlockStore: &corev1.AWSElasticBlockStoreVolumeSource{},
					},
				},
				{
					Name: "volume4",
					VolumeSource: corev1.VolumeSource{
						AWSElasticBlockStore: &corev1.AWSElasticBlockStoreVolumeSource{},
					},
				},
				{
					Name: "permittedVolume",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{},
					},
				},
			}
			Expect(fakeClient.Create(ctx, labeledNamespacePod)).To(Succeed())
		},
			&rules.Options2003{
				AcceptedPods: []option.AcceptedPodVolumes{
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"pod": "bar",
									},
								},
								NamespaceLabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"namespace": "foo",
									},
								},
							},
							Justification: "accepted wildcard",
						},
						VolumeNames: []string{"volume-*"},
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Accepted, Message: "accepted wildcard", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "volume-1")},
				{Status: rule.Accepted, Message: "accepted wildcard", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "volume-2")},
				{Status: rule.Accepted, Message: "accepted wildcard", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "volume-3")},
				{Status: rule.Failed, Message: "Pod uses not allowed volume type.", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "volume4")},
			},
		),
		Entry("should accept all volumes when a full wildcard is used for a volume name", func() {
			labeledNamespace := &corev1.Namespace{}
			labeledNamespace.Name = "labeledNamespace"
			labeledNamespace.Labels = map[string]string{
				"namespace": "foo",
			}
			Expect(fakeClient.Create(ctx, labeledNamespace)).To(Succeed())

			labeledNamespacePod := plainPod.DeepCopy()
			labeledNamespacePod.Name = "labeledNamespacePod"
			labeledNamespacePod.Labels = map[string]string{"pod": "bar"}
			labeledNamespacePod.Namespace = labeledNamespace.Name
			labeledNamespacePod.Spec.Volumes = []corev1.Volume{
				{
					Name: "volume-1",
					VolumeSource: corev1.VolumeSource{
						Cinder: &corev1.CinderVolumeSource{},
					},
				},
				{
					Name: "2volume",
					VolumeSource: corev1.VolumeSource{
						StorageOS: &corev1.StorageOSVolumeSource{},
					},
				},
				{
					Name: "foo-bar",
					VolumeSource: corev1.VolumeSource{
						AWSElasticBlockStore: &corev1.AWSElasticBlockStoreVolumeSource{},
					},
				},
				{
					Name: "baz",
					VolumeSource: corev1.VolumeSource{
						AWSElasticBlockStore: &corev1.AWSElasticBlockStoreVolumeSource{},
					},
				},
			}
			Expect(fakeClient.Create(ctx, labeledNamespacePod)).To(Succeed())
		},
			&rules.Options2003{
				AcceptedPods: []option.AcceptedPodVolumes{
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"pod": "bar",
									},
								},
								NamespaceLabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"namespace": "foo",
									},
								},
							},
							Justification: "accepted full wildcard",
						},
						VolumeNames: []string{"*"},
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Accepted, Message: "accepted full wildcard", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "volume-1")},
				{Status: rule.Accepted, Message: "accepted full wildcard", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "2volume")},
				{Status: rule.Accepted, Message: "accepted full wildcard", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "foo-bar")},
				{Status: rule.Accepted, Message: "accepted full wildcard", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "baz")},
			},
		),

		Entry("should accept a volume if there are more than one options that target it's pod", func() {
			labeledNamespace := &corev1.Namespace{}
			labeledNamespace.Name = "labeledNamespace"
			labeledNamespace.Labels = map[string]string{
				"namespace": "foo",
			}
			Expect(fakeClient.Create(ctx, labeledNamespace)).To(Succeed())

			labeledNamespacePod := plainPod.DeepCopy()
			labeledNamespacePod.Name = "labeledNamespacePod"
			labeledNamespacePod.Labels = map[string]string{"pod": "bar"}
			labeledNamespacePod.Namespace = labeledNamespace.Name
			labeledNamespacePod.Spec.Volumes = []corev1.Volume{
				{
					Name: "volume-suffix",
					VolumeSource: corev1.VolumeSource{
						Cinder: &corev1.CinderVolumeSource{},
					},
				},
				{
					Name: "prefix-volume",
					VolumeSource: corev1.VolumeSource{
						Cinder: &corev1.CinderVolumeSource{},
					},
				},
			}
			Expect(fakeClient.Create(ctx, labeledNamespacePod)).To(Succeed())
		},
			&rules.Options2003{
				AcceptedPods: []option.AcceptedPodVolumes{
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"pod": "bar",
									},
								},
								NamespaceLabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"namespace": "foo",
									},
								},
							},
							Justification: "accepted prefix wildcard",
						},
						VolumeNames: []string{"*-volume"},
					},
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"pod": "bar",
									},
								},
								NamespaceLabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"namespace": "foo",
									},
								},
							},
							Justification: "accepted suffix wildcard",
						},
						VolumeNames: []string{"volume-*"},
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Accepted, Message: "accepted suffix wildcard", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "volume-suffix")},
				{Status: rule.Accepted, Message: "accepted prefix wildcard", Target: rule.NewTarget("kind", "Pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "prefix-volume")},
			},
		),
	)

	It("should return correct targets when pods have owner references", func() {
		r := &rules.Rule2003{Client: fakeClient, Options: &rules.Options2003{}}

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
		Expect(fakeClient.Create(ctx, replicaSet)).To(Succeed())

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
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

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
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(ruleResult.CheckResults).To(Equal(
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Pod uses only allowed volume types.", Target: rule.NewTarget("kind", "Deployment", "name", "foo", "namespace", "foo")},
				{Status: rule.Passed, Message: "Pod uses only allowed volume types.", Target: rule.NewTarget("kind", "DaemonSet", "name", "bar", "namespace", "foo")},
			},
		))
	})

})
