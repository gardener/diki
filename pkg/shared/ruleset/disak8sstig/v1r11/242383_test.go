// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ = Describe("#242383", func() {
	var (
		fakeClient client.Client
		plainPod   *corev1.Pod
		options    *v1r11.Options242383
		ctx        = context.TODO()
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		plainPod = &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind: "Pod",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "foo",
				Labels:    map[string]string{},
			},
		}
		options = &v1r11.Options242383{
			AcceptedResources: []v1r11.AcceptedResources242383{
				{
					MatchLabels: map[string]string{},
				},
			},
		}
	})

	It("should return passed checkResult when no user resources are present in system namespaces", func() {
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

		options.AcceptedResources[0].MatchLabels["label"] = "value"
		options.AcceptedResources[0].Status = "Passed"
		r := &v1r11.Rule242383{
			Client:  fakeClient,
			Options: options,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("System resource in system namespaces.", rule.NewTarget("name", "bar", "namespace", "kube-system", "kind", "Pod")),
			rule.PassedCheckResult("System resource in system namespaces.", rule.NewTarget("name", "bar", "namespace", "kube-public", "kind", "Pod")),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return failed checkResult when user resources are present in system namespaces", func() {
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

		r := &v1r11.Rule242383{Client: fakeClient}

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
		pod.Namespace = "kube-system"
		Expect(fakeClient.Create(ctx, pod)).To(Succeed())

		deployment := &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{
				Kind: "Deployment",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment",
				Namespace: "kube-system",
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

		r := &v1r11.Rule242383{Client: fakeClient}

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

		options.AcceptedResources[0].MatchLabels["foo"] = "bar"
		options.AcceptedResources[0].MatchLabels["bar"] = "foo"
		options.AcceptedResources[0].Status = "Accepted"
		options.AcceptedResources[0].Justification = "Accept pod."
		options.AcceptedResources[0].NamespaceNames = []string{"kube-system"}
		options.AcceptedResources = append(options.AcceptedResources, v1r11.AcceptedResources242383{
			MatchLabels: map[string]string{
				"foo": "bar",
			},
		})
		options.AcceptedResources = append(options.AcceptedResources, v1r11.AcceptedResources242383{
			MatchLabels: map[string]string{
				"foo-bar": "bar",
			},
			Status: "fake",
		})
		r := &v1r11.Rule242383{
			Client:  fakeClient,
			Options: options,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedCheckResults := []rule.CheckResult{
			rule.WarningCheckResult("unrecognized status: fake", rule.NewTarget("name", "pod1", "namespace", "kube-system", "kind", "Pod")),
			rule.AcceptedCheckResult("Accept pod.", rule.NewTarget("name", "bar", "namespace", "kube-system", "kind", "Pod")),
			rule.AcceptedCheckResult("Accepted user resource in system namespaces.", rule.NewTarget("name", "bar", "namespace", "kube-public", "kind", "Pod")),
		}

		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})
})
