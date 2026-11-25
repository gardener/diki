// SPDX-FileCopyrightText: Contributors to the Gardener project
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

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/podsecuritystandards/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
	"github.com/gardener/diki/pkg/shared/kubernetes/option/mergetest"
)

var _ = Describe("#PSS-B001", func() {
	var (
		fakeClient    client.Client
		plainPod      *corev1.Pod
		ctx           = context.TODO()
		namespaceName = "foo"
		namespace     *corev1.Namespace

		// hostProcessSC and hostProcessPodSC are shared helpers that always set HostProcess: true.
		// They are defined here (not in BeforeEach) because they carry no per-test state.
		hostProcessSC = &corev1.SecurityContext{
			WindowsOptions: &corev1.WindowsSecurityContextOptions{
				HostProcess: new(true),
			},
		}
		hostProcessPodSC = &corev1.PodSecurityContext{
			WindowsOptions: &corev1.WindowsSecurityContextOptions{
				HostProcess: new(true),
			},
		}
		acceptedOptions = rules.OptionsPSSB001{
			AcceptedPods: []option.AcceptedNamespacedObject{
				{
					NamespacedObjectSelector: option.NamespacedObjectSelector{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"foo": "bar"},
						},
						NamespaceLabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"foo": "bar"},
						},
					},
					Justification: "foo justify",
				},
			},
		}
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
				Name:      "foo",
				Namespace: namespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "test"},
				},
				InitContainers: []corev1.Container{
					{Name: "initTest"},
				},
				EphemeralContainers: []corev1.EphemeralContainer{
					{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "ephemeralTest"}},
				},
			},
		}
	})

	It("should pass when no pods are present for evaluation", func() {
		r := &rules.RulePSSB001{Client: fakeClient, Options: &rules.OptionsPSSB001{}}
		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			rule.PassedCheckResult("The cluster does not have any Pods.", rule.NewTarget()),
		}))
	})

	DescribeTable("Run cases",
		func(podSC *corev1.PodSecurityContext, containerSC *corev1.SecurityContext, initContainerSC *corev1.SecurityContext, ephemeralContainerSC *corev1.SecurityContext, options rules.OptionsPSSB001, expectedResult rule.CheckResult) {
			r := &rules.RulePSSB001{Client: fakeClient, Options: &options}
			pod := plainPod.DeepCopy()
			pod.Spec.SecurityContext = podSC
			pod.Spec.Containers[0].SecurityContext = containerSC
			pod.Spec.InitContainers[0].SecurityContext = initContainerSC
			pod.Spec.EphemeralContainers[0].SecurityContext = ephemeralContainerSC

			Expect(fakeClient.Create(ctx, pod)).To(Succeed())
			Expect(fakeClient.Create(ctx, namespace)).To(Succeed())

			ruleResult, err := r.Run(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{expectedResult}))
		},

		// nil / unset at every level is SAFE for HostProcess (opt-in feature, secure default),
		// unlike AllowPrivilegeEscalation which is insecure when unset.
		Entry("should pass when security contexts are nil",
			nil, nil, nil, nil, rules.OptionsPSSB001{},
			rule.PassedCheckResult("Pod does not have Host Process ability.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "foo")),
		),
		Entry("should pass when pod security context has nil windows options",
			&corev1.PodSecurityContext{}, nil, nil, nil, rules.OptionsPSSB001{},
			rule.PassedCheckResult("Pod does not have Host Process ability.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "foo")),
		),
		Entry("should pass when container windows options has nil HostProcess",
			nil, &corev1.SecurityContext{WindowsOptions: &corev1.WindowsSecurityContextOptions{}}, nil, nil, rules.OptionsPSSB001{},
			rule.PassedCheckResult("Pod does not have Host Process ability.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "foo")),
		),
		Entry("should pass when HostProcess is set to false",
			nil, &corev1.SecurityContext{WindowsOptions: &corev1.WindowsSecurityContextOptions{HostProcess: new(false)}}, nil, nil, rules.OptionsPSSB001{},
			rule.PassedCheckResult("Pod does not have Host Process ability.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "foo")),
		),
		// Pod-level SecurityContext check: target has no "container" key.
		Entry("should fail when pod-level HostProcess is set to true",
			hostProcessPodSC, nil, nil, nil, rules.OptionsPSSB001{},
			rule.FailedCheckResult("Pod must not have Host Process ability.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "foo")),
		),
		// Per-container checks: target includes "container" key.
		Entry("should fail when container HostProcess is set to true",
			nil, hostProcessSC, nil, nil, rules.OptionsPSSB001{},
			rule.FailedCheckResult("Pod must not have Host Process ability.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "foo", "container", "test")),
		),
		Entry("should fail when initContainer HostProcess is set to true",
			nil, nil, hostProcessSC, nil, rules.OptionsPSSB001{},
			rule.FailedCheckResult("Pod must not have Host Process ability.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "foo", "container", "initTest")),
		),
		Entry("should fail when ephemeralContainer HostProcess is set to true",
			nil, nil, nil, hostProcessSC, rules.OptionsPSSB001{},
			rule.FailedCheckResult("Pod must not have Host Process ability.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "foo", "container", "ephemeralTest")),
		),
		// Accept logic: consulted only after a violation is found (the redesign's guarantee).
		Entry("should accept when container HostProcess is set to true and pod matches accept list",
			nil, hostProcessSC, nil, nil, acceptedOptions,
			rule.AcceptedCheckResult("foo justify", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "foo", "container", "test")),
		),
		Entry("should use default justification when accepted justification is empty",
			nil, hostProcessSC, nil, nil,
			rules.OptionsPSSB001{
				AcceptedPods: []option.AcceptedNamespacedObject{
					{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							LabelSelector:          &metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}},
							NamespaceLabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}},
						},
					},
				},
			},
			rule.AcceptedCheckResult("Pod accepted to have Host Process ability.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "foo", "container", "test")),
		),
		// Key invariant of the redesign: a pod on the accept list that has no violation passes,
		// it does not spuriously return Accepted.
		Entry("should pass when pod matches accept list but HostProcess is not set",
			nil, nil, nil, nil, acceptedOptions,
			rule.PassedCheckResult("Pod does not have Host Process ability.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "foo")),
		),
	)

	It("should return one result per violation when pod and container both have HostProcess set to true", func() {
		r := &rules.RulePSSB001{Client: fakeClient, Options: &rules.OptionsPSSB001{}}
		pod := plainPod.DeepCopy()
		pod.Spec.SecurityContext = hostProcessPodSC
		pod.Spec.Containers[0].SecurityContext = hostProcessSC

		Expect(fakeClient.Create(ctx, pod)).To(Succeed())
		Expect(fakeClient.Create(ctx, namespace)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			rule.FailedCheckResult("Pod must not have Host Process ability.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "foo")),
			rule.FailedCheckResult("Pod must not have Host Process ability.", rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "foo", "container", "test")),
		}))
	})

	It("should return correct targets when pods have owner references", func() {
		r := &rules.RulePSSB001{Client: fakeClient, Options: &rules.OptionsPSSB001{}}

		replicaSet := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: namespaceName,
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
		Expect(fakeClient.Create(ctx, namespace)).To(Succeed())

		// Pod owned by a ReplicaSet, which is owned by a Deployment.
		pod1 := plainPod.DeepCopy()
		pod1.Name = "foo-bar"
		pod1.Spec.Containers[0].SecurityContext = hostProcessSC
		pod1.OwnerReferences = []metav1.OwnerReference{
			{
				UID:        "1",
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "ReplicaSet",
			},
		}
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		// Pod owned directly by a DaemonSet.
		pod2 := plainPod.DeepCopy()
		pod2.Name = "foo-baz"
		pod2.Spec.Containers[0].SecurityContext = hostProcessSC
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
		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			rule.FailedCheckResult("Pod must not have Host Process ability.", rule.NewTarget("kind", "Deployment", "name", "foo", "namespace", "foo", "container", "test")),
			rule.FailedCheckResult("Pod must not have Host Process ability.", rule.NewTarget("kind", "DaemonSet", "name", "bar", "namespace", "foo", "container", "test")),
		}))
	})

	Describe("#Merge OptionsPSSB001", func() {
		It("should merge two OptionsPSSB001 by appending AcceptedPods", func() {
			base := &rules.OptionsPSSB001{
				AcceptedPods: []option.AcceptedNamespacedObject{
					{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							LabelSelector:          &metav1.LabelSelector{MatchLabels: map[string]string{"app": "base"}},
							NamespaceLabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"ns": "base"}},
						},
						Justification: "base justification",
					},
				},
			}
			override := &rules.OptionsPSSB001{
				AcceptedPods: []option.AcceptedNamespacedObject{
					{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							LabelSelector:          &metav1.LabelSelector{MatchLabels: map[string]string{"app": "override"}},
							NamespaceLabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"ns": "override"}},
						},
						Justification: "override justification",
					},
				},
			}

			merged, err := base.Merge(override)
			Expect(err).ToNot(HaveOccurred())

			mergedOpts, ok := merged.(*rules.OptionsPSSB001)
			Expect(ok).To(BeTrue())
			Expect(mergedOpts.AcceptedPods).To(HaveLen(2))
			Expect(mergedOpts.AcceptedPods[0].Justification).To(Equal("base justification"))
			Expect(mergedOpts.AcceptedPods[1].Justification).To(Equal("override justification"))
		})

		It("should handle merging two empty OptionsPSSB001", func() {
			base := &rules.OptionsPSSB001{}
			other := &rules.OptionsPSSB001{}

			merged, err := base.Merge(other)
			Expect(err).ToNot(HaveOccurred())

			mergedOpts, ok := merged.(*rules.OptionsPSSB001)
			Expect(ok).To(BeTrue())
			Expect(mergedOpts.AcceptedPods).To(BeEmpty())
		})

		mergetest.AssertNilOtherReturnsReceiver(&rules.OptionsPSSB001{
			AcceptedPods: []option.AcceptedNamespacedObject{{Justification: "base"}},
		})
		mergetest.AssertWrongTypeErrors(&rules.OptionsPSSB001{}, &option.ClusterObjectSelector{})
	})
})
