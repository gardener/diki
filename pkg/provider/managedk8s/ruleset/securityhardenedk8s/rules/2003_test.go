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
		Entry("should pass when no pod volumes are found",
			func() {},
			nil,
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "No pod volumes found for evaluation.", Target: rule.NewTarget()},
			},
		),
		Entry("should pass when all pod volumes are of an accepted type",
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
				{Status: rule.Passed, Message: "The Pod volume is of an acceptable type.", Target: rule.NewTarget("kind", "pod", "name", "podWithPermittedVolumes", "namespace", "plainNamespace", "volume", "configMapVolume")},
				{Status: rule.Passed, Message: "The Pod volume is of an acceptable type.", Target: rule.NewTarget("kind", "pod", "name", "podWithPermittedVolumes", "namespace", "plainNamespace", "volume", "emptyDirVolume")},
				{Status: rule.Passed, Message: "The Pod volume is of an acceptable type.", Target: rule.NewTarget("kind", "pod", "name", "podWithPermittedVolumes", "namespace", "plainNamespace", "volume", "projectedVolume")},
			},
		),
		Entry("should fail when a pod volume is not of an accepted type",
			func() {
				podWithPermittedVolumes := plainPod.DeepCopy()
				podWithPermittedVolumes.Name = "podWithPermittedVolumes"
				podWithPermittedVolumes.Spec.Volumes = []corev1.Volume{
					{
						Name: "emptyDirVolume",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
					{
						Name: "projectedVolume",
						VolumeSource: corev1.VolumeSource{
							Cinder: &corev1.CinderVolumeSource{},
						},
					},
				}
				Expect(fakeClient.Create(ctx, podWithPermittedVolumes)).To(Succeed())
			},
			nil,
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "The Pod volume is of an acceptable type.", Target: rule.NewTarget("kind", "pod", "name", "podWithPermittedVolumes", "namespace", "plainNamespace", "volume", "emptyDirVolume")},
				{Status: rule.Failed, Message: "The Pod volume is not of an acceptable type.", Target: rule.NewTarget("kind", "pod", "name", "podWithPermittedVolumes", "namespace", "plainNamespace", "volume", "projectedVolume")},
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
				AcceptedPods: []rules.AcceptedPods2003{
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
								NamespaceMatchLabels: map[string]string{
									"foo": "bar",
								},
								MatchLabels: map[string]string{
									"podFoo": "podBar",
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
				{Status: rule.Accepted, Message: "justification 1", Target: rule.NewTarget("kind", "pod", "name", "acceptedPod", "namespace", "plainNamespace", "volume", "acceptedVolume1")},
				{Status: rule.Passed, Message: "The Pod volume is of an acceptable type.", Target: rule.NewTarget("kind", "pod", "name", "acceptedPod", "namespace", "plainNamespace", "volume", "permittedVolume1")},
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
				AcceptedPods: []rules.AcceptedPods2003{
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
								NamespaceMatchLabels: map[string]string{
									"foo": "bar",
								},
								MatchLabels: map[string]string{
									"podFoo": "podBar",
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
				{Status: rule.Accepted, Message: "justification 1", Target: rule.NewTarget("kind", "pod", "name", "acceptedPod", "namespace", "plainNamespace", "volume", "acceptedVolume1")},
				{Status: rule.Passed, Message: "The Pod volume is of an acceptable type.", Target: rule.NewTarget("kind", "pod", "name", "acceptedPod", "namespace", "plainNamespace", "volume", "permittedVolume1")},
				{Status: rule.Passed, Message: "The Pod volume is of an acceptable type.", Target: rule.NewTarget("kind", "pod", "name", "acceptedPod", "namespace", "plainNamespace", "volume", "permittedVolume2")},
				{Status: rule.Failed, Message: "The Pod volume is not of an acceptable type.", Target: rule.NewTarget("kind", "pod", "name", "acceptedPod", "namespace", "plainNamespace", "volume", "forbiddenVolume1")},
				{Status: rule.Failed, Message: "The Pod volume is not of an acceptable type.", Target: rule.NewTarget("kind", "pod", "name", "regularPod", "namespace", "plainNamespace", "volume", "acceptedVolume1")},
				{Status: rule.Passed, Message: "The Pod volume is of an acceptable type.", Target: rule.NewTarget("kind", "pod", "name", "regularPod", "namespace", "plainNamespace", "volume", "permittedVolume1")},
				{Status: rule.Failed, Message: "The Pod volume is not of an acceptable type.", Target: rule.NewTarget("kind", "pod", "name", "regularPod", "namespace", "plainNamespace", "volume", "forbiddenVolume1")},
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
				AcceptedPods: []rules.AcceptedPods2003{
					{
						AcceptedNamespacedObject: option.AcceptedNamespacedObject{
							NamespacedObjectSelector: option.NamespacedObjectSelector{
								NamespaceMatchLabels: map[string]string{
									"label": "baz",
								},
								MatchLabels: map[string]string{
									"podFoo": "podBar",
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
				{Status: rule.Failed, Message: "The Pod volume is not of an acceptable type.", Target: rule.NewTarget("kind", "pod", "name", "plainNamespacePod", "namespace", "plainNamespace", "volume", "forbiddenVolume1")},
				{Status: rule.Accepted, Message: "justification 1", Target: rule.NewTarget("kind", "pod", "name", "labeledNamespacePod", "namespace", "labeledNamespace", "volume", "acceptedVolume1")},
			},
		),
	)

	Describe("#ValidateOptions2003", func() {
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

			result := options.Validate()

			Expect(result).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":   Equal(field.ErrorTypeRequired),
					"Field":  Equal("acceptedPods.volumeNames"),
					"Detail": Equal("must not be empty"),
				})),
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("acceptedPods.volumeNames[0]"),
					"BadValue": Equal(""),
					"Detail":   Equal("must not be empty"),
				})),
			))
		})
	})
})
