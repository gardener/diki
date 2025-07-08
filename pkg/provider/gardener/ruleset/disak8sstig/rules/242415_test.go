// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
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

	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ = Describe("#242415", func() {
	var (
		fakeSeedClient     client.Client
		fakeShootClient    client.Client
		options            *option.Options242415
		seedPod            *corev1.Pod
		shootPod           *corev1.Pod
		ctx                = context.TODO()
		seedNamespaceName  = "seed"
		shootNamespaceName = "shoot"
		seedNamespace      *corev1.Namespace
		shootNamespace     *corev1.Namespace
	)

	BeforeEach(func() {
		fakeSeedClient = fakeclient.NewClientBuilder().Build()
		fakeShootClient = fakeclient.NewClientBuilder().Build()

		shootNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: shootNamespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
		}

		seedNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: seedNamespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
		}

		seedPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "seed-pod",
				Namespace: seedNamespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "test",
						Env:  []corev1.EnvVar{},
					},
				},
			},
		}
		shootPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shoot-pod",
				Namespace: shootNamespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "test",
						Env:  []corev1.EnvVar{},
					},
				},
			},
		}
		options = &option.Options242415{}
	})

	It("should return correct results when all pods pass", func() {
		r := &rules.Rule242415{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: seedNamespaceName, Options: options}
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not use environment to inject secret.",
				Target:  rule.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "seed", "kind", "Pod"),
			},
			{
				Status:  rule.Passed,
				Message: "Pod does not use environment to inject secret.",
				Target:  rule.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "shoot", "kind", "Pod"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when a pod fails", func() {
		r := &rules.Rule242415{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: seedNamespaceName, Options: options}
		shootPod.Spec.Containers[0].Env = []corev1.EnvVar{
			{
				Name: "SECRET_TEST",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						Key: "secret_test",
					},
				},
			},
		}
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not use environment to inject secret.",
				Target:  rule.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "seed", "kind", "Pod"),
			},
			{
				Status:  rule.Failed,
				Message: "Pod uses environment to inject secret.",
				Target:  rule.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "shoot", "kind", "Pod", "container", "test", "details", "variableName: SECRET_TEST, keyRef: secret_test"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when a pod contains an initContainer", func() {
		r := &rules.Rule242415{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: seedNamespaceName, Options: options}
		shootPod.Spec.InitContainers = []corev1.Container{
			{
				Name: "initFoo",
				Env: []corev1.EnvVar{
					{
						Name: "SECRET_TEST",
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								Key: "secret_test",
							},
						},
					},
				},
			},
		}
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not use environment to inject secret.",
				Target:  rule.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "seed", "kind", "Pod"),
			},
			{
				Status:  rule.Failed,
				Message: "Pod uses environment to inject secret.",
				Target:  rule.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "shoot", "kind", "Pod", "container", "initFoo", "details", "variableName: SECRET_TEST, keyRef: secret_test"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when a pod has accepted environment variables", func() {
		options = &option.Options242415{
			AcceptedPods: []option.AcceptedPods242415{
				{
					PodSelector: option.PodSelector{
						PodMatchLabels:       map[string]string{"foo": "bar"},
						NamespaceMatchLabels: map[string]string{"foo": "bar"},
					},
					EnvironmentVariables: []string{"SECRET_TEST"},
				},
			},
		}
		r := &rules.Rule242415{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: seedNamespaceName, Options: options}
		shootPod.Spec.Containers[0].Env = []corev1.EnvVar{
			{
				Name: "SECRET_TEST",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						Key: "secret_test",
					},
				},
			},
		}

		Expect(fakeSeedClient.Create(ctx, seedNamespace)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootNamespace)).To(Succeed())
		Expect(fakeSeedClient.Create(ctx, seedPod)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootPod)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []rule.CheckResult{
			{
				Status:  rule.Passed,
				Message: "Pod does not use environment to inject secret.",
				Target:  rule.NewTarget("cluster", "seed", "name", "seed-pod", "namespace", "seed", "kind", "Pod"),
			},
			{
				Status:  rule.Accepted,
				Message: "Pod accepted to use environment to inject secret.",
				Target:  rule.NewTarget("cluster", "shoot", "name", "shoot-pod", "namespace", "shoot", "kind", "Pod", "container", "test", "details", "variableName: SECRET_TEST, keyRef: secret_test"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct targets when the pods have owner references", func() {
		r := &rules.Rule242415{ClusterClient: fakeShootClient, ControlPlaneClient: fakeSeedClient, ControlPlaneNamespace: seedNamespaceName}

		shootReplicaSet := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: shootNamespaceName,
				UID:       "1",
				Name:      "shootReplicaSet",
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind:       "Deployment",
						APIVersion: "apps/v1",
						Name:       "shootFoo",
					},
				},
			},
		}
		Expect(fakeShootClient.Create(ctx, shootReplicaSet)).To(Succeed())

		shootPod1 := shootPod.DeepCopy()
		shootPod1.Name = "shoot-pod-1"
		shootPod1.OwnerReferences = []metav1.OwnerReference{
			{
				UID:        "1",
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "ReplicaSet",
			},
		}
		Expect(fakeShootClient.Create(ctx, shootPod1)).To(Succeed())

		shootPod2 := shootPod.DeepCopy()
		shootPod2.Name = "shoot-pod-2"
		shootPod2.OwnerReferences = []metav1.OwnerReference{
			{
				UID:        "1",
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "ReplicaSet",
			},
		}
		Expect(fakeShootClient.Create(ctx, shootPod2)).To(Succeed())

		seedReplicaSet := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "seedReplicaSet",
				UID:       "2",
				Namespace: seedNamespaceName,
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       "Deployment",
						Name:       "seedFoo",
					},
				},
			},
		}
		Expect(fakeSeedClient.Create(ctx, seedReplicaSet)).To(Succeed())

		seedPod1 := seedPod.DeepCopy()
		seedPod1.Name = "seed-pod-1"
		seedPod1.OwnerReferences = []metav1.OwnerReference{
			{
				UID:        "2",
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "ReplicaSet",
			},
		}
		Expect(fakeSeedClient.Create(ctx, seedPod1)).To(Succeed())

		seedPod2 := seedPod.DeepCopy()
		seedPod2.Name = "seed-pod-2"
		seedPod2.OwnerReferences = []metav1.OwnerReference{
			{
				UID:        "2",
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "ReplicaSet",
			},
		}
		Expect(fakeSeedClient.Create(ctx, seedPod2)).To(Succeed())

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			{Status: rule.Passed, Message: "Pod does not use environment to inject secret.", Target: rule.NewTarget("cluster", "seed", "namespace", "seed", "kind", "Deployment", "name", "seedFoo")},
			{Status: rule.Passed, Message: "Pod does not use environment to inject secret.", Target: rule.NewTarget("cluster", "shoot", "namespace", "shoot", "kind", "Deployment", "name", "shootFoo")},
		}))

	})

})
