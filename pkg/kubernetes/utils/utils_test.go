// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/kubernetes/config"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("utils", func() {
	Describe("#GetObjectsMetadata", func() {
		var (
			fakeClient       client.Client
			ctx              = context.TODO()
			namespaceFoo     = "foo"
			namespaceDefault = "default"
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			for i := 0; i < 10; i++ {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceDefault,
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name: "test",
							},
						},
					},
				}
				Expect(fakeClient.Create(ctx, pod)).To(Succeed())
			}
			for i := 10; i < 12; i++ {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceDefault,
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
					},
				}
				Expect(fakeClient.Create(ctx, pod)).To(Succeed())
			}
			for i := 0; i < 6; i++ {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceFoo,
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name: "test",
							},
						},
					},
				}
				Expect(fakeClient.Create(ctx, pod)).To(Succeed())
			}
			for i := 0; i < 3; i++ {
				node := &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: strconv.Itoa(i),
					},
				}
				Expect(fakeClient.Create(ctx, node)).To(Succeed())
			}
		})

		It("should return correct number of pods in default namespace", func() {
			pods, err := utils.GetObjectsMetadata(ctx, fakeClient, corev1.SchemeGroupVersion.WithKind("PodList"), namespaceDefault, labels.NewSelector(), 2)

			Expect(len(pods)).To(Equal(12))
			Expect(err).To(BeNil())
		})

		It("should return correct number of pods in foo namespace", func() {
			pods, err := utils.GetObjectsMetadata(ctx, fakeClient, corev1.SchemeGroupVersion.WithKind("PodList"), namespaceFoo, labels.NewSelector(), 2)

			Expect(len(pods)).To(Equal(6))
			Expect(err).To(BeNil())
		})

		It("should return correct number of pods in all namespaces", func() {
			pods, err := utils.GetObjectsMetadata(ctx, fakeClient, corev1.SchemeGroupVersion.WithKind("PodList"), "", labels.NewSelector(), 2)

			Expect(len(pods)).To(Equal(18))
			Expect(err).To(BeNil())
		})

		It("should return correct number of labeled pods in default namespace", func() {
			pods, err := utils.GetObjectsMetadata(ctx, fakeClient, corev1.SchemeGroupVersion.WithKind("PodList"), namespaceDefault, labels.SelectorFromSet(labels.Set{"foo": "bar"}), 2)

			Expect(len(pods)).To(Equal(2))
			Expect(err).To(BeNil())
		})

		It("should return correct number of nodes", func() {
			nodes, err := utils.GetObjectsMetadata(ctx, fakeClient, corev1.SchemeGroupVersion.WithKind("NodeList"), "", labels.NewSelector(), 2)

			Expect(len(nodes)).To(Equal(3))
			Expect(err).To(BeNil())
		})
	})

	Describe("#GetAllObjectsMetadata", func() {
		var (
			fakeClient              client.Client
			ctx                     = context.TODO()
			pod                     *corev1.Pod
			replicationController   *corev1.ReplicationController
			service                 *corev1.Service
			deployment              *appsv1.Deployment
			daemonSet               *appsv1.DaemonSet
			replicaSet              *appsv1.ReplicaSet
			statefulSet             *appsv1.StatefulSet
			horizontalPodAutoscaler *autoscalingv1.HorizontalPodAutoscaler
			job                     *batchv1.Job
			cronJob                 *batchv1.CronJob
			namespaceFoo            = "foo"
			namespaceDefault        = "default"
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			pod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod",
					Namespace: namespaceDefault,
					Labels: map[string]string{
						"foo": "bar",
					},
				},
			}
			Expect(fakeClient.Create(ctx, pod)).To(Succeed())

			replicationController = &corev1.ReplicationController{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "replicationController",
					Namespace: namespaceDefault,
				},
			}
			Expect(fakeClient.Create(ctx, replicationController)).To(Succeed())

			service = &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "service",
					Namespace: namespaceFoo,
				},
			}
			Expect(fakeClient.Create(ctx, service)).To(Succeed())

			deployment = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deployment",
					Namespace: namespaceDefault,
				},
			}
			Expect(fakeClient.Create(ctx, deployment)).To(Succeed())

			daemonSet = &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "daemonSet",
					Namespace: namespaceDefault,
				},
			}
			Expect(fakeClient.Create(ctx, daemonSet)).To(Succeed())

			replicaSet = &appsv1.ReplicaSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "replicaSet",
					Namespace: namespaceDefault,
				},
			}
			Expect(fakeClient.Create(ctx, replicaSet)).To(Succeed())

			statefulSet = &appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "statefulSet",
					Namespace: namespaceFoo,
					Labels: map[string]string{
						"foo": "bar",
					},
				},
			}
			Expect(fakeClient.Create(ctx, statefulSet)).To(Succeed())

			horizontalPodAutoscaler = &autoscalingv1.HorizontalPodAutoscaler{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "horizontalPodAutoscaler",
					Namespace: namespaceFoo,
				},
			}
			Expect(fakeClient.Create(ctx, horizontalPodAutoscaler)).To(Succeed())

			job = &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "job",
					Namespace: namespaceDefault,
				},
			}
			Expect(fakeClient.Create(ctx, job)).To(Succeed())

			cronJob = &batchv1.CronJob{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cronJob",
					Namespace: namespaceFoo,
				},
			}
			Expect(fakeClient.Create(ctx, cronJob)).To(Succeed())
		})

		It("should return correct number of resources in default namespace", func() {
			pods, err := utils.GetAllObjectsMetadata(ctx, fakeClient, namespaceDefault, labels.NewSelector(), 2)

			Expect(len(pods)).To(Equal(6))
			Expect(err).To(BeNil())
		})

		It("should return correct number of resources in foo namespace", func() {
			resources, err := utils.GetAllObjectsMetadata(ctx, fakeClient, namespaceFoo, labels.NewSelector(), 2)

			Expect(len(resources)).To(Equal(4))
			Expect(err).To(BeNil())
		})

		It("should return correct number of resources in all namespaces", func() {
			resources, err := utils.GetAllObjectsMetadata(ctx, fakeClient, "", labels.NewSelector(), 2)

			Expect(len(resources)).To(Equal(10))
			Expect(err).To(BeNil())
		})

		It("should return correct number of labeled resources", func() {
			resources, err := utils.GetAllObjectsMetadata(ctx, fakeClient, "", labels.SelectorFromSet(labels.Set{"foo": "bar"}), 2)

			Expect(len(resources)).To(Equal(2))
			Expect(err).To(BeNil())
		})
	})

	Describe("#FilterPodsByOwnerRef", func() {
		var (
			plainPod *corev1.Pod
		)

		BeforeEach(func() {
			plainPod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
			}
		})

		It("should return empty list when no pods are provided", func() {
			pods := utils.FilterPodsByOwnerRef(nil)

			Expect(pods).To(BeEmpty())
		})
		It("should return all pods when all have unique owner references", func() {
			pod1 := plainPod.DeepCopy()
			pod1.Name = "pod1"

			pod2 := plainPod.DeepCopy()
			pod2.Name = "pod2"
			pod2.OwnerReferences = []metav1.OwnerReference{
				{
					UID: "1",
				},
			}

			pod3 := plainPod.DeepCopy()
			pod3.Name = "pod3"
			pod3.OwnerReferences = []metav1.OwnerReference{
				{
					UID: "2",
				},
			}

			pod4 := plainPod.DeepCopy()
			pod4.Name = "pod4"

			podList := []corev1.Pod{*pod1, *pod2, *pod3, *pod4}
			res := utils.FilterPodsByOwnerRef(podList)

			Expect(res).To(ConsistOf(podList))
		})

		It("should filter out pods with not unique owner references", func() {
			pod1 := plainPod.DeepCopy()
			pod1.Name = "pod1"

			pod2 := plainPod.DeepCopy()
			pod2.Name = "pod2"
			pod2.OwnerReferences = []metav1.OwnerReference{
				{
					UID: "1",
				},
			}

			pod3 := plainPod.DeepCopy()
			pod3.Name = "pod3"
			pod3.OwnerReferences = []metav1.OwnerReference{
				{
					UID: "1",
				},
			}

			res := utils.FilterPodsByOwnerRef([]corev1.Pod{*pod1, *pod2, *pod3})

			Expect(res).To(ConsistOf([]corev1.Pod{*pod1, *pod2}))
		})
	})

	Describe("#GetPods", func() {
		var (
			fakeClient       client.Client
			ctx              = context.TODO()
			namespaceFoo     = "foo"
			namespaceDefault = "default"
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			for i := 0; i < 10; i++ {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceDefault,
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name: "test",
							},
						},
					},
				}
				Expect(fakeClient.Create(ctx, pod)).To(Succeed())
			}
			for i := 10; i < 12; i++ {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceDefault,
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
					},
				}
				Expect(fakeClient.Create(ctx, pod)).To(Succeed())
			}
			for i := 0; i < 6; i++ {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceFoo,
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name: "test",
							},
						},
					},
				}
				Expect(fakeClient.Create(ctx, pod)).To(Succeed())
			}
		})

		It("should return correct number of pods in default namespace", func() {
			pods, err := utils.GetPods(ctx, fakeClient, namespaceDefault, labels.NewSelector(), 2)

			Expect(len(pods)).To(Equal(12))
			Expect(err).To(BeNil())
		})

		It("should return correct number of pods in foo namespace", func() {
			pods, err := utils.GetPods(ctx, fakeClient, namespaceFoo, labels.NewSelector(), 2)

			Expect(len(pods)).To(Equal(6))
			Expect(err).To(BeNil())
		})

		It("should return correct number of pods in all namespaces", func() {
			pods, err := utils.GetPods(ctx, fakeClient, "", labels.NewSelector(), 2)

			Expect(len(pods)).To(Equal(18))
			Expect(err).To(BeNil())
		})

		It("should return correct number of labeled pods in default namespace", func() {
			pods, err := utils.GetPods(ctx, fakeClient, namespaceDefault, labels.SelectorFromSet(labels.Set{"foo": "bar"}), 2)

			Expect(len(pods)).To(Equal(2))
			Expect(err).To(BeNil())
		})

	})

	Describe("#GetServices", func() {
		var (
			fakeClient       client.Client
			ctx              = context.TODO()
			namespaceFoo     = "foo"
			namespaceDefault = "default"
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			for i := 0; i < 10; i++ {
				service := &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceDefault,
					},
				}
				Expect(fakeClient.Create(ctx, service)).To(Succeed())
			}
			for i := 10; i < 12; i++ {
				service := &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceDefault,
						Labels: map[string]string{
							"foo": "bar",
						},
					},
				}
				Expect(fakeClient.Create(ctx, service)).To(Succeed())
			}
			for i := 0; i < 6; i++ {
				service := &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceFoo,
					},
				}
				Expect(fakeClient.Create(ctx, service)).To(Succeed())
			}
		})

		It("should return correct number of services in default namespace", func() {
			services, err := utils.GetServices(ctx, fakeClient, namespaceDefault, labels.NewSelector(), 2)

			Expect(len(services)).To(Equal(12))
			Expect(err).To(BeNil())
		})

		It("should return correct number of services in foo namespace", func() {
			services, err := utils.GetServices(ctx, fakeClient, namespaceFoo, labels.NewSelector(), 2)

			Expect(len(services)).To(Equal(6))
			Expect(err).To(BeNil())
		})

		It("should return correct number of services in all namespaces", func() {
			services, err := utils.GetServices(ctx, fakeClient, "", labels.NewSelector(), 2)

			Expect(len(services)).To(Equal(18))
			Expect(err).To(BeNil())
		})

		It("should return correct number of labeled services in default namespace", func() {
			services, err := utils.GetServices(ctx, fakeClient, namespaceDefault, labels.SelectorFromSet(labels.Set{"foo": "bar"}), 2)

			Expect(len(services)).To(Equal(2))
			Expect(err).To(BeNil())
		})

	})

	Describe("#GetRoles", func() {
		var (
			fakeClient       client.Client
			ctx              = context.TODO()
			namespaceFoo     = "foo"
			namespaceDefault = "default"
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			for i := 0; i < 10; i++ {
				role := &rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceDefault,
					},
				}
				Expect(fakeClient.Create(ctx, role)).To(Succeed())
			}
			for i := 10; i < 12; i++ {
				role := &rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceDefault,
						Labels: map[string]string{
							"foo": "bar",
						},
					},
				}
				Expect(fakeClient.Create(ctx, role)).To(Succeed())
			}
			for i := 0; i < 6; i++ {
				role := &rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceFoo,
					},
				}
				Expect(fakeClient.Create(ctx, role)).To(Succeed())
			}
		})

		It("should return correct number of roles in default namespace", func() {
			roles, err := utils.GetRoles(ctx, fakeClient, namespaceDefault, labels.NewSelector(), 2)

			Expect(len(roles)).To(Equal(12))
			Expect(err).To(BeNil())
		})

		It("should return correct number of roles in foo namespace", func() {
			roles, err := utils.GetRoles(ctx, fakeClient, namespaceFoo, labels.NewSelector(), 2)

			Expect(len(roles)).To(Equal(6))
			Expect(err).To(BeNil())
		})

		It("should return correct number of roles in all namespaces", func() {
			roles, err := utils.GetRoles(ctx, fakeClient, "", labels.NewSelector(), 2)

			Expect(len(roles)).To(Equal(18))
			Expect(err).To(BeNil())
		})

		It("should return correct number of labeled roles in default namespace", func() {
			roles, err := utils.GetRoles(ctx, fakeClient, namespaceDefault, labels.SelectorFromSet(labels.Set{"foo": "bar"}), 2)

			Expect(len(roles)).To(Equal(2))
			Expect(err).To(BeNil())
		})

	})

	Describe("#GetClusterRoles", func() {
		var (
			fakeClient client.Client
			ctx        = context.TODO()
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			for i := 0; i < 10; i++ {
				clusterRole := &rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: strconv.Itoa(i),
					},
				}
				Expect(fakeClient.Create(ctx, clusterRole)).To(Succeed())
			}
			for i := 10; i < 12; i++ {
				clusterRole := &rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: strconv.Itoa(i),
						Labels: map[string]string{
							"foo": "bar",
						},
					},
				}
				Expect(fakeClient.Create(ctx, clusterRole)).To(Succeed())
			}
		})

		It("should return correct number of clusterRoles", func() {
			clusterRoles, err := utils.GetClusterRoles(ctx, fakeClient, labels.NewSelector(), 2)

			Expect(len(clusterRoles)).To(Equal(12))
			Expect(err).To(BeNil())
		})

		It("should return correct number of labeled clusterRoles", func() {
			clusterRoles, err := utils.GetClusterRoles(ctx, fakeClient, labels.SelectorFromSet(labels.Set{"foo": "bar"}), 2)

			Expect(len(clusterRoles)).To(Equal(2))
			Expect(err).To(BeNil())
		})

	})

	Describe("#GetReplicaSets", func() {
		var (
			fakeClient       client.Client
			ctx              = context.TODO()
			namespaceFoo     = "foo"
			namespaceDefault = "default"
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			for i := 0; i < 10; i++ {
				replicaSet := &appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceDefault,
					},
					Spec: appsv1.ReplicaSetSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "test",
									},
								},
							},
						},
					},
				}
				Expect(fakeClient.Create(ctx, replicaSet)).To(Succeed())
			}
			for i := 10; i < 12; i++ {
				replicaSet := &appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceDefault,
						Labels: map[string]string{
							"foo": "bar",
						},
					},
					Spec: appsv1.ReplicaSetSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "test",
									},
								},
							},
						},
					},
				}
				Expect(fakeClient.Create(ctx, replicaSet)).To(Succeed())
			}
			for i := 0; i < 6; i++ {
				replicaSet := &appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceFoo,
					},
					Spec: appsv1.ReplicaSetSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "test",
									},
								},
							},
						},
					},
				}
				Expect(fakeClient.Create(ctx, replicaSet)).To(Succeed())
			}
		})

		It("should return correct number of replicaSets in default namespace", func() {
			replicaSets, err := utils.GetReplicaSets(ctx, fakeClient, namespaceDefault, labels.NewSelector(), 2)

			Expect(len(replicaSets)).To(Equal(12))
			Expect(err).To(BeNil())
		})

		It("should return correct number of replicaSets in foo namespace", func() {
			replicaSets, err := utils.GetReplicaSets(ctx, fakeClient, namespaceFoo, labels.NewSelector(), 2)

			Expect(len(replicaSets)).To(Equal(6))
			Expect(err).To(BeNil())
		})

		It("should return correct number of replicaSets in all namespaces", func() {
			replicaSets, err := utils.GetReplicaSets(ctx, fakeClient, "", labels.NewSelector(), 2)

			Expect(len(replicaSets)).To(Equal(18))
			Expect(err).To(BeNil())
		})

		It("should return correct number of labeled replicaSets in default namespace", func() {
			replicaSets, err := utils.GetReplicaSets(ctx, fakeClient, namespaceDefault, labels.SelectorFromSet(labels.Set{"foo": "bar"}), 2)

			Expect(len(replicaSets)).To(Equal(2))
			Expect(err).To(BeNil())
		})
	})

	Describe("#GetNetworkPolicies", func() {
		var (
			fakeClient       client.Client
			ctx              = context.TODO()
			namespaceFoo     = "foo"
			namespaceDefault = "default"
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			for i := 0; i < 10; i++ {
				networkPolicy := &networkingv1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceDefault,
					},
				}
				Expect(fakeClient.Create(ctx, networkPolicy)).To(Succeed())
			}
			for i := 10; i < 12; i++ {
				networkPolicy := &networkingv1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceDefault,
						Labels: map[string]string{
							"foo": "bar",
						},
					},
				}
				Expect(fakeClient.Create(ctx, networkPolicy)).To(Succeed())
			}
			for i := 0; i < 6; i++ {
				networkPolicy := &networkingv1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespaceFoo,
					},
				}
				Expect(fakeClient.Create(ctx, networkPolicy)).To(Succeed())
			}
		})

		It("should return correct number of networkPolicies in default namespace", func() {
			networkPolicies, err := utils.GetNetworkPolicies(ctx, fakeClient, namespaceDefault, labels.NewSelector(), 2)

			Expect(len(networkPolicies)).To(Equal(12))
			Expect(err).To(BeNil())
		})

		It("should return correct number of networkPolicies in foo namespace", func() {
			networkPolicies, err := utils.GetNetworkPolicies(ctx, fakeClient, namespaceFoo, labels.NewSelector(), 2)

			Expect(len(networkPolicies)).To(Equal(6))
			Expect(err).To(BeNil())
		})

		It("should return correct number of networkPolicies in all namespaces", func() {
			networkPolicies, err := utils.GetNetworkPolicies(ctx, fakeClient, "", labels.NewSelector(), 2)

			Expect(len(networkPolicies)).To(Equal(18))
			Expect(err).To(BeNil())
		})

		It("should return correct number of labeled networkPolicies in default namespace", func() {
			networkPolicies, err := utils.GetNetworkPolicies(ctx, fakeClient, namespaceDefault, labels.SelectorFromSet(labels.Set{"foo": "bar"}), 2)

			Expect(len(networkPolicies)).To(Equal(2))
			Expect(err).To(BeNil())
		})
	})

	Describe("#GetStorageClasses", func() {
		var (
			fakeClient client.Client
			ctx        = context.TODO()
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			for i := 0; i < 4; i++ {
				storageClass := storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: strconv.Itoa(i),
					},
				}
				Expect(fakeClient.Create(ctx, &storageClass)).To(BeNil())
			}
			for i := 4; i < 6; i++ {
				storageClass := storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: strconv.Itoa(i),
						Labels: map[string]string{
							"foo": "bar",
						},
					},
				}
				Expect(fakeClient.Create(ctx, &storageClass)).To(BeNil())
			}
		})

		It("should return correct number of storageClasses", func() {
			storageClasses, err := utils.GetStorageClasses(ctx, fakeClient, labels.NewSelector(), 4)
			Expect(len(storageClasses)).To(Equal(6))
			Expect(err).To(BeNil())
		})
		It("should return correct number of labeled storageClasses", func() {
			storageClasses, err := utils.GetStorageClasses(ctx, fakeClient, labels.SelectorFromSet(labels.Set{"foo": "bar"}), 4)
			Expect(len(storageClasses)).To(Equal(2))
			Expect(err).To(BeNil())
		})
	})

	Describe("#GetDeploymentPods", func() {
		var (
			fakeClient      client.Client
			ctx             = context.TODO()
			basicDeployment *appsv1.Deployment
			basicReplicaSet *appsv1.ReplicaSet
			basicPod        *corev1.Pod
			namespace       = "foo"
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			basicDeployment = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: namespace,
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "test",
								},
							},
						},
					},
				},
			}
			basicReplicaSet = &appsv1.ReplicaSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: namespace,
				},
				Spec: appsv1.ReplicaSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "test",
								},
							},
						},
					},
				},
			}
			basicPod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: namespace,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "test",
						},
					},
				},
			}

		})

		It("should return pods of a deployment", func() {
			deployment := basicDeployment.DeepCopy()
			deployment.UID = "1"
			replicaSet := basicReplicaSet.DeepCopy()
			replicaSet.OwnerReferences = []metav1.OwnerReference{
				{
					Name: "foo",
					UID:  "1",
					Kind: "Deployment",
				},
			}
			replicaSet.Spec.Replicas = ptr.To[int32](1)
			replicaSet.UID = "2"
			pod := basicPod.DeepCopy()
			pod.OwnerReferences = []metav1.OwnerReference{
				{
					Name: "foo",
					UID:  "2",
					Kind: "ReplicaSet",
				},
			}
			Expect(fakeClient.Create(ctx, deployment)).To(Succeed())
			Expect(fakeClient.Create(ctx, replicaSet)).To(Succeed())
			Expect(fakeClient.Create(ctx, pod)).To(Succeed())

			pods, err := utils.GetDeploymentPods(ctx, fakeClient, "foo", namespace)

			Expect(pods).To(Equal([]corev1.Pod{*pod}))
			Expect(err).To(BeNil())
		})

		It("should return error when deployment not found", func() {
			pods, err := utils.GetDeploymentPods(ctx, fakeClient, "foo", namespace)

			Expect(pods).To(BeNil())
			Expect(err).To(MatchError("deployments.apps \"foo\" not found"))
		})

		It("should not return pods when relicaSet replicase are 0", func() {
			deployment := basicDeployment.DeepCopy()
			deployment.UID = "1"
			replicaSet := basicReplicaSet.DeepCopy()
			replicaSet.OwnerReferences = []metav1.OwnerReference{
				{
					Name: "foo",
					UID:  "1",
					Kind: "Deployment",
				},
			}
			replicaSet.Spec.Replicas = ptr.To[int32](0)
			replicaSet.UID = "2"
			pod := basicPod.DeepCopy()
			pod.OwnerReferences = []metav1.OwnerReference{
				{
					Name: "foo",
					UID:  "2",
					Kind: "ReplicaSet",
				},
			}
			Expect(fakeClient.Create(ctx, deployment)).To(Succeed())
			Expect(fakeClient.Create(ctx, replicaSet)).To(Succeed())
			Expect(fakeClient.Create(ctx, pod)).To(Succeed())

			pods, err := utils.GetDeploymentPods(ctx, fakeClient, "foo", namespace)

			Expect(pods).To(HaveLen(0))
			Expect(err).To(BeNil())
		})

		It("should return pods when relicaSet replicase are not specified", func() {
			deployment := basicDeployment.DeepCopy()
			deployment.UID = "1"
			replicaSet := basicReplicaSet.DeepCopy()
			replicaSet.OwnerReferences = []metav1.OwnerReference{
				{
					Name: "foo",
					UID:  "1",
					Kind: "Deployment",
				},
			}
			replicaSet.UID = "2"
			pod := basicPod.DeepCopy()
			pod.OwnerReferences = []metav1.OwnerReference{
				{
					Name: "foo",
					UID:  "2",
					Kind: "ReplicaSet",
				},
			}
			Expect(fakeClient.Create(ctx, deployment)).To(Succeed())
			Expect(fakeClient.Create(ctx, replicaSet)).To(Succeed())
			Expect(fakeClient.Create(ctx, pod)).To(Succeed())

			pods, err := utils.GetDeploymentPods(ctx, fakeClient, "foo", namespace)

			Expect(pods).To(Equal([]corev1.Pod{*pod}))
			Expect(err).To(BeNil())
		})

		It("should return multiple pods", func() {
			deployment := basicDeployment.DeepCopy()
			deployment.UID = "1"
			replicaSet1 := basicReplicaSet.DeepCopy()
			replicaSet1.Name = "foo1"
			replicaSet1.OwnerReferences = []metav1.OwnerReference{
				{
					Name: "foo",
					UID:  "1",
					Kind: "Deployment",
				},
			}
			replicaSet1.UID = "2"
			replicaSet2 := basicReplicaSet.DeepCopy()
			replicaSet2.Name = "foo2"
			replicaSet2.OwnerReferences = []metav1.OwnerReference{
				{
					Name: "foo",
					UID:  "1",
					Kind: "Deployment",
				},
			}
			replicaSet2.UID = "3"
			pod1 := basicPod.DeepCopy()
			pod1.Name = "foo1"
			pod1.OwnerReferences = []metav1.OwnerReference{
				{
					Name: "foo",
					UID:  "2",
					Kind: "ReplicaSet",
				},
			}
			pod2 := basicPod.DeepCopy()
			pod2.Name = "foo2"
			pod2.OwnerReferences = []metav1.OwnerReference{
				{
					Name: "foo",
					UID:  "2",
					Kind: "ReplicaSet",
				},
			}
			pod3 := basicPod.DeepCopy()
			pod3.Name = "foo3"
			pod3.OwnerReferences = []metav1.OwnerReference{
				{
					Name: "foo",
					UID:  "3",
					Kind: "ReplicaSet",
				},
			}
			pod4 := basicPod.DeepCopy()
			pod4.Name = "foo4"
			Expect(fakeClient.Create(ctx, deployment)).To(Succeed())
			Expect(fakeClient.Create(ctx, replicaSet1)).To(Succeed())
			Expect(fakeClient.Create(ctx, replicaSet2)).To(Succeed())
			Expect(fakeClient.Create(ctx, pod1)).To(Succeed())
			Expect(fakeClient.Create(ctx, pod2)).To(Succeed())
			Expect(fakeClient.Create(ctx, pod3)).To(Succeed())
			Expect(fakeClient.Create(ctx, pod4)).To(Succeed())

			pods, err := utils.GetDeploymentPods(ctx, fakeClient, "foo", namespace)

			Expect(pods).To(Equal([]corev1.Pod{*pod1, *pod2, *pod3}))
			Expect(err).To(BeNil())
		})
	})

	Describe("#GetNodes", func() {
		var (
			fakeClient client.Client
			ctx        = context.TODO()
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			for i := 0; i < 6; i++ {
				node := &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: strconv.Itoa(i),
					},
				}
				Expect(fakeClient.Create(ctx, node)).To(Succeed())
			}
		})

		It("should return correct number of nodes", func() {
			nodes, err := utils.GetNodes(ctx, fakeClient, 2)

			Expect(len(nodes)).To(Equal(6))
			Expect(err).To(BeNil())
		})
	})

	Describe("#GetNamespaces", func() {
		var (
			fakeClient client.Client
			ctx        = context.TODO()
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			for i := 0; i < 3; i++ {
				namespace := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: strconv.Itoa(i),
					},
				}
				Expect(fakeClient.Create(ctx, namespace)).To(Succeed())
			}
		})

		It("should return correct namespace map", func() {
			namespaces, err := utils.GetNamespaces(ctx, fakeClient)

			expectedNamespaces := map[string]corev1.Namespace{
				"0": {
					ObjectMeta: metav1.ObjectMeta{
						Name:            "0",
						ResourceVersion: "1",
					},
				},
				"1": {
					ObjectMeta: metav1.ObjectMeta{
						Name:            "1",
						ResourceVersion: "1",
					},
				},
				"2": {
					ObjectMeta: metav1.ObjectMeta{
						Name:            "2",
						ResourceVersion: "1",
					},
				},
			}

			Expect(namespaces).To(Equal(expectedNamespaces))
			Expect(err).To(BeNil())
		})
	})

	DescribeTable("#GetContainerFromDeployment",
		func(deployment *appsv1.Deployment, containerName string, expectedContainer corev1.Container, expectedFound bool) {
			container, found := utils.GetContainerFromDeployment(deployment, containerName)

			Expect(container).To(Equal(expectedContainer))

			Expect(found).To(Equal(expectedFound))
		},

		Entry("should return correct container",
			&appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "container1",
								},
								{
									Name: "container2",
								},
								{
									Name: "container3",
								},
							},
						},
					},
				},
			}, "container2", corev1.Container{Name: "container2"}, true),
		Entry("should return found false when container not found",
			&appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "container1",
								},
							},
						},
					},
				},
			}, "container2", corev1.Container{}, false),
	)

	DescribeTable("#GetContainerFromStatefulSet",
		func(statefulSet *appsv1.StatefulSet, containerName string, expectedContainer corev1.Container, expectedFound bool) {
			container, found := utils.GetContainerFromStatefulSet(statefulSet, containerName)

			Expect(container).To(Equal(expectedContainer))

			Expect(found).To(Equal(expectedFound))
		},

		Entry("should return correct container",
			&appsv1.StatefulSet{
				Spec: appsv1.StatefulSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "container1",
								},
								{
									Name: "container2",
								},
								{
									Name: "container3",
								},
							},
						},
					},
				},
			}, "container2", corev1.Container{Name: "container2"}, true),
		Entry("should return found false when container not found",
			&appsv1.StatefulSet{
				Spec: appsv1.StatefulSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "container1",
								},
							},
						},
					},
				},
			}, "container2", corev1.Container{}, false),
	)

	DescribeTable("#GetVolumeFromStatefulSet",
		func(statefulSet *appsv1.StatefulSet, volumeName string, expectedVolume corev1.Volume, expectedFound bool) {
			volume, found := utils.GetVolumeFromStatefulSet(statefulSet, volumeName)

			Expect(volume).To(Equal(expectedVolume))

			Expect(found).To(Equal(expectedFound))
		},

		Entry("should return correct volume",
			&appsv1.StatefulSet{
				Spec: appsv1.StatefulSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Volumes: []corev1.Volume{
								{
									Name: "volume1",
								},
								{
									Name: "volume2",
								},
								{
									Name: "volume3",
								},
							},
						},
					},
				},
			}, "volume2", corev1.Volume{Name: "volume2"}, true),
		Entry("should return found false when volume not found",
			&appsv1.StatefulSet{
				Spec: appsv1.StatefulSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Volumes: []corev1.Volume{
								{
									Name: "volume1",
								},
							},
						},
					},
				},
			}, "volume2", corev1.Volume{}, false),
	)

	DescribeTable("#FindFlagValueRaw ",
		func(command []string, flag string, expectedResult []string) {
			result := utils.FindFlagValueRaw(command, flag)

			Expect(result).To(Equal(expectedResult))
		},

		Entry("should correctly find value for flag",
			[]string{"--flag1=value1", "--flag2=value2", "--flag3 value3", "--flag4=value4", "--flag5=value5"},
			"flag1",
			[]string{"value1"}),
		Entry("should correctly find values for flag starts with --",
			[]string{"--flag1=value1", "--flag2=value2", "--flag1", "value3", "--flag1 value4", "--flag1foo=value5", "--flag1", "--barflag1=value6"},
			"flag1",
			[]string{"value1", "value3", "value4", ""}),
		Entry("should correctly find values for flag starts with -",
			[]string{"-flag1=value1", "-flag2=value2", "-flag1", "value3", "-flag1 value4", "-flag1foo=value5", "-flag1", "-barflag1=value6"},
			"flag1",
			[]string{"value1", "value3", "value4", ""}),
		Entry("ambiguous behavior",
			[]string{"--flag1=value1 --flag2=value2", "-flag1=     value3", "--flag1=\"value4\"", "-flag1      "},
			"flag1",
			[]string{"value1 --flag2=value2", "value3", "\"value4\"", ""}),
		Entry("should return values that have inner flags",
			[]string{"--flag1=value1=value1.1,value2=value2.1", "--flag2=value2", "--flag3=value3=value3.1", "--flag4=value4", "--flag1=value5=value5.1"},
			"flag1",
			[]string{"value1=value1.1,value2=value2.1", "value5=value5.1"}),
		Entry("should trim whitespaces from values",
			[]string{"--flag1  value1 ", "--flag2=value2", "--flag1 value3", "--flag4=value4", "--flag1=value5 "},
			"flag1",
			[]string{"value1", "value3", "value5"}),
	)

	DescribeTable("#FindInnerValue",
		func(values []string, flag string, expectedResult []string) {
			result := utils.FindInnerValue(values, flag)

			Expect(result).To(Equal(expectedResult))
		},
		Entry("should correctly find values for flag",
			[]string{"flag1=value1,flag2=value2,flag3=value3", "flag4=value2", "flag4=value4,flag1=value5"},
			"flag1",
			[]string{"value1", "value5"}),
		Entry("should correctly find multiple values of the same flag in a single string",
			[]string{"flag1=value1,flag2=value2,flag1=value3", "flag4=value2", "flag4=value4,flag5=value5"},
			"flag1",
			[]string{"value1", "value3"}),
		Entry("should return empty string when no values are found",
			[]string{"flag1=value1,flag2=value2,flag3=value3", "flag4=value2", "flag4=value4,flag1=value5"},
			"flag6",
			nil),
	)

	Describe("#GetVolumeConfigByteSlice", func() {
		var (
			fakeClient client.Client
			ctx        = context.TODO()
			volume     corev1.Volume
			namespace  = "foo"
			fileName   = "foo"
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			volume = corev1.Volume{}
		})

		It("should return correct data when volume is ConfigMap", func() {
			volume.ConfigMap = &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "foo",
				},
			}
			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: namespace,
				},
				Data: map[string]string{
					fileName: "foo",
				},
			}
			Expect(fakeClient.Create(ctx, configMap)).To(Succeed())
			byteSlice, err := utils.GetFileDataFromVolume(ctx, fakeClient, namespace, volume, fileName)

			Expect(err).To(BeNil())
			Expect(byteSlice).To(Equal([]byte("foo")))
		})

		It("should return error when ConfigMap is not found", func() {
			volume.ConfigMap = &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "foo",
				},
			}
			byteSlice, err := utils.GetFileDataFromVolume(ctx, fakeClient, namespace, volume, fileName)

			Expect(err).To(MatchError("configmaps \"foo\" not found"))
			Expect(byteSlice).To(BeNil())
		})

		It("should return error when ConfigMap does not have Data field with file name", func() {
			volume.ConfigMap = &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "foo",
				},
			}
			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: namespace,
				},
				Data: map[string]string{},
			}
			Expect(fakeClient.Create(ctx, configMap)).To(Succeed())
			byteSlice, err := utils.GetFileDataFromVolume(ctx, fakeClient, namespace, volume, fileName)

			Expect(err).To(MatchError("configMap: foo does not contain filed: foo in Data field"))
			Expect(byteSlice).To(BeNil())
		})

		It("should return correct data when volume is Secret", func() {
			volume.Secret = &corev1.SecretVolumeSource{
				SecretName: "foo",
			}
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					fileName: []byte("foo"),
				},
			}
			Expect(fakeClient.Create(ctx, secret)).To(Succeed())
			byteSlice, err := utils.GetFileDataFromVolume(ctx, fakeClient, namespace, volume, fileName)

			Expect(err).To(BeNil())
			Expect(byteSlice).To(Equal([]byte("foo")))
		})

		It("should return error when Secret is not found", func() {
			volume.Secret = &corev1.SecretVolumeSource{
				SecretName: "foo",
			}
			byteSlice, err := utils.GetFileDataFromVolume(ctx, fakeClient, namespace, volume, fileName)

			Expect(err).To(MatchError("secrets \"foo\" not found"))
			Expect(byteSlice).To(BeNil())
		})

		It("should return error when Secret does not have Data field with file name", func() {
			volume.Secret = &corev1.SecretVolumeSource{
				SecretName: "foo",
			}
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: namespace,
				},
				Data: map[string][]byte{},
			}
			Expect(fakeClient.Create(ctx, secret)).To(Succeed())
			byteSlice, err := utils.GetFileDataFromVolume(ctx, fakeClient, namespace, volume, fileName)

			Expect(err).To(MatchError("secret: foo does not contain filed: foo in Data field"))
			Expect(byteSlice).To(BeNil())
		})

		It("should return error when volume type is not supported", func() {
			byteSlice, err := utils.GetFileDataFromVolume(ctx, fakeClient, namespace, volume, fileName)

			Expect(err).To(MatchError(fmt.Sprintf("cannot handle volume: %v", volume)))
			Expect(byteSlice).To(BeNil())
		})
	})

	Describe("#GetCommandOptionFromDeployment", func() {
		var (
			fakeClient     client.Client
			ctx            = context.TODO()
			namespace      = "foo"
			deploymentName = "foo"
			containerName  = "foo"
			deployment     *appsv1.Deployment
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			deployment = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deploymentName,
					Namespace: namespace,
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: containerName,
									Command: []string{
										"--foo=bar",
										"--bar1=foo1",
									},
									Args: []string{
										"--foo2=bar2",
										"--bar1=foo3",
									},
								},
							},
						},
					},
				},
			}
			Expect(fakeClient.Create(ctx, deployment)).To(Succeed())
		})

		DescribeTable("Run cases",
			func(deploymentName, containerName, namespace, option string, expectedResults []string, errorMatcher gomegatypes.GomegaMatcher) {
				result, err := utils.GetCommandOptionFromDeployment(ctx, fakeClient, deploymentName, containerName, namespace, option)
				Expect(err).To(errorMatcher)

				Expect(result).To(Equal(expectedResults))
			},
			Entry("should return correct values for flag",
				deploymentName, containerName, namespace, "foo", []string{"bar"}, BeNil()),
			Entry("should return correct values for flag when there are more than 1 occurances",
				deploymentName, containerName, namespace, "bar1", []string{"foo1", "foo3"}, BeNil()),
			Entry("should return empty slice when the options is missing",
				deploymentName, containerName, namespace, "foo5", nil, BeNil()),
			Entry("should return error when the deployment is missing",
				"test", containerName, namespace, "foo", nil, MatchError("deployments.apps \"test\" not found")),
			Entry("should return error when the container is missing",
				deploymentName, "test", namespace, "foo", nil, MatchError("deployment: foo does not contain container: test")),
		)

	})

	Describe("#GetVolumeConfigByteSliceByMountPath", func() {
		var (
			fakeClient     client.Client
			ctx            = context.TODO()
			namespace      = "foo"
			deploymentName = "foo"
			containerName  = "foo"
			mountPath      = "foo/bar/fileName.yaml"
			fileName       = "fileName.yaml"
			configMapName  = "kube-apiserver-admission-config"
			configMapData  = "configMapData"
			deployment     *appsv1.Deployment
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			deployment = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deploymentName,
					Namespace: namespace,
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: containerName,
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "admission-config-cm",
											MountPath: "foo/bar",
										},
									},
								},
							},
							Volumes: []corev1.Volume{
								{
									Name: "admission-config-cm",
									VolumeSource: corev1.VolumeSource{
										ConfigMap: &corev1.ConfigMapVolumeSource{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: configMapName,
											},
										},
									},
								},
							},
						},
					},
				},
			}
			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: namespace,
				},
				Data: map[string]string{
					fileName: configMapData,
				},
			}
			Expect(fakeClient.Create(ctx, deployment)).To(Succeed())
			Expect(fakeClient.Create(ctx, configMap)).To(Succeed())
		})

		It("Should return correct volume data", func() {
			result, err := utils.GetVolumeConfigByteSliceByMountPath(ctx, fakeClient, deployment, containerName, mountPath)

			Expect(err).To(BeNil())

			Expect(result).To(Equal([]byte(configMapData)))
		})

		It("Should error when there is no container with containerName", func() {
			nonExistentContainer := "bar"
			result, err := utils.GetVolumeConfigByteSliceByMountPath(ctx, fakeClient, deployment, nonExistentContainer, mountPath)

			Expect(err).To(MatchError("deployment does not contain container with name: bar"))

			Expect(result).To(BeNil())
		})

		It("Should error when there is no volumeMount with mountPath", func() {
			nonExistentMountPath := "bar/foo/fileName.yaml"
			result, err := utils.GetVolumeConfigByteSliceByMountPath(ctx, fakeClient, deployment, containerName, nonExistentMountPath)

			Expect(err).To(MatchError("cannot find volume with path bar/foo/fileName.yaml"))

			Expect(result).To(BeNil())
		})

		It("Should error when there is no volume with name from volumeMount", func() {
			deployment.Spec.Template.Spec.Volumes = []corev1.Volume{}
			result, err := utils.GetVolumeConfigByteSliceByMountPath(ctx, fakeClient, deployment, containerName, mountPath)

			Expect(err).To(MatchError("deployment does not contain volume with name: admission-config-cm"))

			Expect(result).To(BeNil())
		})
	})

	Describe("#GetKubeletCommand", func() {
		var (
			fakePodExecutor *fakepod.FakePodExecutor
			ctx             context.Context
			commandMessage  string
		)
		BeforeEach(func() {
			commandMessage = "message foo"
			ctx = context.TODO()
		})

		DescribeTable("#MatchCases",
			func(executeReturnString []string, executeReturnError []error, expectedMessage string, errorMatcher gomegatypes.GomegaMatcher) {
				fakePodExecutor = fakepod.NewFakePodExecutor(executeReturnString, executeReturnError)
				result, err := utils.GetKubeletCommand(ctx, fakePodExecutor)

				Expect(err).To(errorMatcher)
				Expect(result).To(Equal(expectedMessage))
			},
			Entry("should return command message",
				[]string{"1\n", commandMessage}, []error{nil, nil}, commandMessage, BeNil()),
			Entry("should return error when PID is 0",
				[]string{"0\n"}, []error{nil}, "", MatchError("kubelet service is not running")),
			Entry("should return error when first command errors",
				[]string{"1\n"}, []error{errors.New("command error")}, "", MatchError("command error")),
			Entry("should return error when second command errors",
				[]string{"1\n", commandMessage}, []error{nil, errors.New("command error")}, "", MatchError("command error")),
		)
	})

	Describe("#GetContainerCommand", func() {
		var (
			pod corev1.Pod
		)
		BeforeEach(func() {
			pod = corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    "foo",
							Command: []string{"sudo", "su"},
							Args:    []string{"foo"},
						},
						{
							Name:    "bar",
							Command: []string{""},
							Args:    []string{""},
						},
					},
				},
			}
		})

		DescribeTable("#MatchCases",
			func(containerName string, command, args []string, expectedResult string, errorMatcher gomegatypes.GomegaMatcher) {
				pod.Spec.Containers[1].Command = command
				pod.Spec.Containers[1].Args = args
				result, err := utils.GetContainerCommand(pod, containerName)

				Expect(err).To(errorMatcher)
				Expect(result).To(Equal(expectedResult))
			},
			Entry("should return cotainer command", "bar",
				[]string{"/bin/sh", "-c", "exec", "kube-proxy"}, []string{"--kubeconfig=/var/lib/kube-proxy/kubeconfig"},
				"/bin/sh -c exec kube-proxy --kubeconfig=/var/lib/kube-proxy/kubeconfig", BeNil()),
			Entry("should return error when container is not found", "not-bar",
				[]string{}, []string{},
				"", MatchError("pod does not contain a container with name in [not-bar]")),
		)
	})

	Describe("#FindFileMountSource", func() {

		It("should find the correct mount source", func() {
			mounts := []config.Mount{
				{
					Destination: "/foo/bar",
					Source:      "/wrong/source",
				},
				{
					Destination: "/foo-bar",
					Source:      "/again/wrong/source",
				},
				{
					Destination: "/bar/foo",
					Source:      "/correct/source",
				},
			}
			filePath := "/bar/foo/file.txt"

			result, err := utils.FindFileMountSource(filePath, mounts)

			Expect(err).To(BeNil())
			Expect(result).To(Equal("/correct/source/file.txt"))
		})

		It("should return correct sourcec path when destination matches filePath", func() {
			mounts := []config.Mount{
				{
					Destination: "/foo/bar",
					Source:      "/wrong/source",
				},
				{
					Destination: "/foo-bar",
					Source:      "/again/wrong/source",
				},
				{
					Destination: "/bar/foo/file.txt",
					Source:      "/correct/source/file1.txt",
				},
			}
			filePath := "/bar/foo/file.txt"

			result, err := utils.FindFileMountSource(filePath, mounts)

			Expect(err).To(BeNil())
			Expect(result).To(Equal("/correct/source/file1.txt"))
		})

		It("should find most decisive source path", func() {
			mounts := []config.Mount{
				{
					Destination: "/",
					Source:      "/wrong/source",
				},
				{
					Destination: "/bar",
					Source:      "/again/wrong/source",
				},
				{
					Destination: "/bar/fooo",
					Source:      "/correct/source",
				},
				{
					Destination: "/bar/foo",
					Source:      "/correct/source",
				},
			}
			filePath := "/bar/foo/file.txt"

			result, err := utils.FindFileMountSource(filePath, mounts)

			Expect(err).To(BeNil())
			Expect(result).To(Equal("/correct/source/file.txt"))
		})

		It("should return error when source path cannot be found", func() {
			mounts := []config.Mount{
				{
					Destination: "/foo/bar",
					Source:      "/wrong/source",
				},
				{
					Destination: "/foo-bar",
					Source:      "/again/wrong/source",
				},
				{
					Destination: "/bar/foo",
					Source:      "/correct/source",
				},
			}
			filePath := "/bar/fo/file.txt"

			result, err := utils.FindFileMountSource(filePath, mounts)

			Expect(err).To(MatchError("could not find source path for /bar/fo/file.txt"))
			Expect(result).To(Equal(""))
		})
	})

	Describe("#IsFlagSet", func() {
		DescribeTable("#MatchCases",
			func(rawKubeletCommand string, expectedResult bool) {
				result := utils.IsFlagSet(rawKubeletCommand, "set-flag")

				Expect(result).To(Equal(expectedResult))
			},
			Entry("should return false when flag is not set",
				"--foo=bar --not-set-flag=true", false),
			Entry("should return true when flag is set",
				"--foo=bar --set-flag=true", true),
			Entry("should return true when flag is set multiple times",
				"--foo=bar --set-flag=true --set-flag=false", true),
		)
	})

	Describe("#GetKubeletConfig", func() {
		const (
			kubeletConfig = `maxPods: 111
readOnlyPort: 222
`
		)
		var (
			fakePodExecutor *fakepod.FakePodExecutor
			ctx             context.Context
		)
		BeforeEach(func() {
			ctx = context.TODO()
		})

		DescribeTable("#MatchCases",
			func(executeReturnString []string, executeReturnError []error, rawKubeletCommand string, expectedKubeletConfig *config.KubeletConfig, errorMatcher gomegatypes.GomegaMatcher) {
				fakePodExecutor = fakepod.NewFakePodExecutor(executeReturnString, executeReturnError)
				result, err := utils.GetKubeletConfig(ctx, fakePodExecutor, rawKubeletCommand)

				Expect(err).To(errorMatcher)
				Expect(result).To(Equal(expectedKubeletConfig))
			},
			Entry("should return correct kubelet config",
				[]string{kubeletConfig}, []error{nil}, "--foo=./bar --config=./config",
				&config.KubeletConfig{MaxPods: ptr.To[int32](111), ReadOnlyPort: ptr.To[int32](222)}, BeNil()),
			Entry("should return error if no kubelet config is set in command",
				[]string{kubeletConfig}, []error{nil}, "--foo=./bar",
				&config.KubeletConfig{}, MatchError("kubelet config file has not been set")),
			Entry("should return error if more than 1 kubelet config is set in command",
				[]string{kubeletConfig}, []error{nil}, "--config=./config --foo=./bar --config=./config2",
				&config.KubeletConfig{}, MatchError("kubelet config file has been set more than once")),
			Entry("should return error if pod execute command errors",
				[]string{kubeletConfig}, []error{errors.New("command error")}, "--config=./config",
				&config.KubeletConfig{}, MatchError("command error")),
		)
	})

	Describe("#GetKubeProxyConfig", func() {
		const (
			kubeProxyConfig = `clientConnection:
  kubeconfig: /foo/bar/kubeconfig
`
		)
		var (
			fakePodExecutor *fakepod.FakePodExecutor
			ctx             context.Context
		)
		BeforeEach(func() {
			ctx = context.TODO()
		})

		DescribeTable("#MatchCases",
			func(executeReturnString []string, executeReturnError []error, expectedKubeProxyConfig *config.KubeProxyConfig, errorMatcher gomegatypes.GomegaMatcher) {
				fakePodExecutor = fakepod.NewFakePodExecutor(executeReturnString, executeReturnError)
				result, err := utils.GetKubeProxyConfig(ctx, fakePodExecutor, "")

				Expect(err).To(errorMatcher)
				Expect(result).To(Equal(expectedKubeProxyConfig))
			},
			Entry("should return correct kube-proxy config",
				[]string{kubeProxyConfig}, []error{nil},
				&config.KubeProxyConfig{ClientConnection: config.KPClientConnection{Kubeconfig: "/foo/bar/kubeconfig"}}, BeNil()),
			Entry("should return error when command errors",
				[]string{kubeProxyConfig}, []error{errors.New("command error")},
				&config.KubeProxyConfig{}, MatchError("command error")),
		)
	})

	Describe("#GetNodesAllocatablePodsNum", func() {
		It("should correct number of allocatable pods", func() {
			pod1 := &corev1.Pod{}
			pod1.Name = "pod1"
			pod1.Spec.NodeName = "node1"

			pod2 := &corev1.Pod{}
			pod2.Name = "pod2"
			pod2.Spec.NodeName = "node2"

			pod3 := &corev1.Pod{}
			pod3.Name = "pod3"
			pod3.Spec.NodeName = "node1"

			pod4 := &corev1.Pod{}
			pod4.Name = "pod4"
			pod4.Spec.NodeName = "node2"

			pod5 := &corev1.Pod{}
			pod5.Name = "pod5"
			pod5.Spec.NodeName = "node3"

			pods := []corev1.Pod{*pod1, *pod2, *pod3, *pod4, *pod5}

			node1 := &corev1.Node{}
			node1.Name = "node1"
			node1.Status.Allocatable = corev1.ResourceList{
				"pods": resource.MustParse("2.0"),
			}

			node2 := &corev1.Node{}
			node2.Name = "node2"
			node2.Status.Allocatable = corev1.ResourceList{
				"pods": resource.MustParse("5.0"),
			}

			node3 := &corev1.Node{}
			node3.Name = "node3"
			node3.Status.Allocatable = corev1.ResourceList{
				"pods": resource.MustParse("10.0"),
			}

			nodes := []corev1.Node{*node1, *node2, *node3}

			expectedRes := map[string]int{
				"node1": 0,
				"node2": 3,
				"node3": 9,
			}

			res := utils.GetNodesAllocatablePodsNum(pods, nodes)

			Expect(res).To(Equal(expectedRes))
		})

		It("should correct number of allocatable pods when some pods are not scheduled.", func() {
			pod1 := &corev1.Pod{}
			pod1.Name = "pod1"

			pod2 := &corev1.Pod{}
			pod2.Name = "pod2"
			pod2.Spec.NodeName = "node2"

			pod3 := &corev1.Pod{}
			pod3.Name = "pod3"
			pod3.Spec.NodeName = "node1"

			pod4 := &corev1.Pod{}
			pod4.Name = "pod4"

			pod5 := &corev1.Pod{}
			pod5.Name = "pod5"

			pods := []corev1.Pod{*pod1, *pod2, *pod3, *pod4, *pod5}

			node1 := &corev1.Node{}
			node1.Name = "node1"
			node1.Status.Allocatable = corev1.ResourceList{
				"pods": resource.MustParse("2.0"),
			}

			node2 := &corev1.Node{}
			node2.Name = "node2"
			node2.Status.Allocatable = corev1.ResourceList{
				"pods": resource.MustParse("5.0"),
			}

			node3 := &corev1.Node{}
			node3.Name = "node3"
			node3.Status.Allocatable = corev1.ResourceList{
				"pods": resource.MustParse("10.0"),
			}

			nodes := []corev1.Node{*node1, *node2, *node3}

			expectedRes := map[string]int{
				"node1": 1,
				"node2": 4,
				"node3": 10,
			}

			res := utils.GetNodesAllocatablePodsNum(pods, nodes)

			Expect(res).To(Equal(expectedRes))
		})
	})

	Describe("#SelectPodOfReferenceGroup", func() {
		var (
			nodesAllocatablePods map[string]int
			node1                corev1.Node
			node2                corev1.Node
			node3                corev1.Node
			node4                corev1.Node
			nodes                []corev1.Node
		)

		BeforeEach(func() {
			nodesAllocatablePods = map[string]int{
				"node1": 10,
				"node2": 10,
				"node3": 10,
				"node4": 10,
			}

			node1 = corev1.Node{}
			node1.Labels = map[string]string{}
			node1.Name = "node1"

			node2 = corev1.Node{}
			node2.Labels = map[string]string{}
			node2.Name = "node2"

			node3 = corev1.Node{}
			node3.Labels = map[string]string{}
			node3.Name = "node3"

			node4 = corev1.Node{}
			node4.Labels = map[string]string{}
			node4.Name = "node4"

			nodes = []corev1.Node{node1, node2, node3, node4}
		})

		It("should return nodes by unique single label value combination", func() {
			nodes[0].Labels["label"] = "foo"
			nodes[1].Labels["label"] = "bar"
			nodes[2].Labels["label"] = "foo"
			nodes[3].Labels["label"] = "bar"

			res, checkResult := utils.SelectNodes(nodes, nodesAllocatablePods, []string{"label"})

			expectedRes := []corev1.Node{node1, node2}
			Expect(res).To(ConsistOf(expectedRes))
			Expect(checkResult).To(HaveLen(0))
		})

		It("should return nodes by unique label value combination", func() {
			nodes[0].Labels["label1"] = "foo"
			nodes[1].Labels["label1"] = "foo"
			nodes[2].Labels["label1"] = "foo"
			nodes[3].Labels["label1"] = "bar"
			nodes[0].Labels["label2"] = "foo"
			nodes[1].Labels["label2"] = "bar"
			nodes[2].Labels["label2"] = "foo"
			nodes[3].Labels["label2"] = "bar"

			res, checkResult := utils.SelectNodes(nodes, nodesAllocatablePods, []string{"label1", "label2"})

			expectedRes := []corev1.Node{node1, node2, node4}
			Expect(res).To(ConsistOf(expectedRes))
			Expect(checkResult).To(HaveLen(0))
		})

		It("should return warning chackResult when node does not label", func() {
			nodes[0].Labels["label"] = "foo"
			nodes[1].Labels["label"] = "foo"
			nodes[3].Labels["label"] = "bar"

			res, checkResult := utils.SelectNodes(nodes, nodesAllocatablePods, []string{"label"})

			expectedRes := []corev1.Node{node1, node4}
			expectedCheckResults := []rule.CheckResult{
				{
					Status:  rule.Warning,
					Message: "Node is missing a label",
					Target:  rule.NewTarget("kind", "Node", "name", "node3", "label", "label"),
				},
			}

			Expect(res).To(ConsistOf(expectedRes))
			Expect(checkResult).To(Equal(expectedCheckResults))
		})

		It("should return correct checkResults when a combination does not have allocatable nodes", func() {
			nodes[0].Labels["label1"] = "foo"
			nodes[1].Labels["label1"] = "foo"
			nodes[2].Labels["label1"] = "foo"
			nodes[3].Labels["label1"] = "bar"
			nodes[0].Labels["label2"] = "foo"
			nodes[1].Labels["label2"] = "bar"
			nodes[2].Labels["label2"] = "foo"
			nodes[3].Labels["label2"] = "bar"

			nodesAllocatablePods = map[string]int{
				"node1": 0,
				"node2": 0,
				"node3": 10,
				"node4": 0,
			}

			res, checkResult := utils.SelectNodes(nodes, nodesAllocatablePods, []string{"label1", "label2"})

			expectedRes := []corev1.Node{node3}
			expectedCheckResults := []rule.CheckResult{
				{
					Status:  rule.Warning,
					Message: "No allocatable nodes of label value combination",
					Target:  rule.NewTarget("labels", "label1=foo,label2=bar"),
				},
				{
					Status:  rule.Warning,
					Message: "No allocatable nodes of label value combination",
					Target:  rule.NewTarget("labels", "label1=bar,label2=bar"),
				},
			}

			Expect(res).To(ConsistOf(expectedRes))
			Expect(checkResult).To(ConsistOf(expectedCheckResults))
		})

		It("should return all allocatable nodes when labels are not specified", func() {
			nodesAllocatablePods["node3"] = 0

			res, checkResult := utils.SelectNodes(nodes, nodesAllocatablePods, []string{})

			expectedRes := []corev1.Node{node1, node2, node4}
			Expect(res).To(ConsistOf(expectedRes))
			Expect(checkResult).To(HaveLen(0))
		})
	})

	Describe("#SelectPodOfReferenceGroup", func() {
		var (
			nodesAllocatablePods map[string]int
		)

		BeforeEach(func() {
			nodesAllocatablePods = map[string]int{
				"node1": 10,
				"node2": 10,
				"node3": 10,
			}
		})

		It("should group single pods by nodes", func() {
			pod1 := &corev1.Pod{}
			pod1.Name = "pod1"
			pod1.Spec.NodeName = "node1"

			pod2 := &corev1.Pod{}
			pod2.Name = "pod2"
			pod2.Spec.NodeName = "node2"

			pod3 := &corev1.Pod{}
			pod3.Name = "pod3"
			pod3.Spec.NodeName = "node1"

			pod4 := &corev1.Pod{}
			pod4.Name = "pod4"
			pod4.Spec.NodeName = "node2"

			pod5 := &corev1.Pod{}
			pod5.Name = "pod5"
			pod5.Spec.NodeName = "node3"

			pods := []corev1.Pod{*pod1, *pod2, *pod3, *pod4, *pod5}

			expectedRes := map[string][]corev1.Pod{
				"node1": {*pod1, *pod3},
				"node2": {*pod2, *pod4},
				"node3": {*pod5},
			}

			res, checkResult := utils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, rule.Target{})

			Expect(res).To(Equal(expectedRes))
			Expect(checkResult).To(HaveLen(0))
		})

		It("should correclty select pods when reference groups are present", func() {
			pod1 := &corev1.Pod{}
			pod1.Name = "pod1"
			pod1.Spec.NodeName = "node3"
			pod1.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("1"),
				},
			}

			pod2 := &corev1.Pod{}
			pod2.Name = "pod2"
			pod2.Spec.NodeName = "node2"

			pod3 := &corev1.Pod{}
			pod3.Name = "pod3"
			pod3.Spec.NodeName = "node1"

			pod4 := &corev1.Pod{}
			pod4.Name = "pod4"
			pod4.Spec.NodeName = "node2"
			pod4.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("1"),
				},
			}

			pod5 := &corev1.Pod{}
			pod5.Name = "pod5"
			pod5.Spec.NodeName = "node1"
			pod5.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("1"),
				},
			}

			pods := []corev1.Pod{*pod1, *pod2, *pod3, *pod4, *pod5}

			expectedRes := map[string][]corev1.Pod{
				"node1": {*pod3},
				"node2": {*pod2, *pod4},
			}

			res, checkResult := utils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, rule.Target{})

			Expect(res).To(Equal(expectedRes))
			Expect(checkResult).To(HaveLen(0))
		})

		It("should correclty select minimal groups", func() {
			pod1 := &corev1.Pod{}
			pod1.Name = "pod1"
			pod1.Spec.NodeName = "node2"
			pod1.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("1"),
				},
			}

			pod2 := &corev1.Pod{}
			pod2.Name = "pod2"
			pod2.Spec.NodeName = "node1"

			pod3 := &corev1.Pod{}
			pod3.Name = "pod3"
			pod3.Spec.NodeName = "node3"
			pod3.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("2"),
				},
			}

			pod4 := &corev1.Pod{}
			pod4.Name = "pod4"
			pod4.Spec.NodeName = "node3"
			pod4.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("1"),
				},
			}

			pod5 := &corev1.Pod{}
			pod5.Name = "pod5"
			pod5.Spec.NodeName = "node4"
			pod5.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("1"),
				},
			}

			pods := []corev1.Pod{*pod1, *pod2, *pod3, *pod4, *pod5}

			expectedRes := map[string][]corev1.Pod{
				"node1": {*pod2},
				"node3": {*pod3, *pod4},
			}

			res, checkResult := utils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, rule.Target{})

			Expect(res).To(Equal(expectedRes))
			Expect(checkResult).To(HaveLen(0))
		})

		It("should correctly select minimal groups", func() {
			pod1 := &corev1.Pod{}
			pod1.Name = "pod1"
			pod1.Spec.NodeName = "node2"
			pod1.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("1"),
				},
			}

			pod2 := &corev1.Pod{}
			pod2.Name = "pod2"
			pod2.Spec.NodeName = "node1"

			pod3 := &corev1.Pod{}
			pod3.Name = "pod3"
			pod3.Spec.NodeName = "node3"
			pod3.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("2"),
				},
			}

			pod4 := &corev1.Pod{}
			pod4.Name = "pod4"
			pod4.Spec.NodeName = "node3"
			pod4.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("1"),
				},
			}

			pod5 := &corev1.Pod{}
			pod5.Name = "pod5"
			pod5.Spec.NodeName = "node4"
			pod5.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("1"),
				},
			}

			pods := []corev1.Pod{*pod1, *pod2, *pod3, *pod4, *pod5}

			expectedRes := map[string][]corev1.Pod{
				"node1": {*pod2},
				"node3": {*pod3, *pod4},
			}

			res, checkResult := utils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, rule.Target{})

			Expect(res).To(Equal(expectedRes))
			Expect(checkResult).To(HaveLen(0))
		})

		It("should return correct checkResults when pod is not scheduled", func() {
			pod1 := &corev1.Pod{}
			pod1.Name = "pod1"
			pod1.Spec.NodeName = ""

			pods := []corev1.Pod{*pod1}

			expectedRes := map[string][]corev1.Pod{}
			expectedCheckResults := []rule.CheckResult{
				{
					Status:  rule.Warning,
					Message: "Pod not (yet) scheduled",
					Target:  rule.NewTarget("name", "pod1", "namespace", "", "kind", "Pod"),
				},
			}

			res, checkResult := utils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, rule.Target{})

			Expect(res).To(Equal(expectedRes))
			Expect(checkResult).To(Equal(expectedCheckResults))
		})

		It("should return correct checkResults when nodes are fully allocated", func() {
			pod1 := &corev1.Pod{}
			pod1.Name = "pod1"
			pod1.Spec.NodeName = "node3"
			pod1.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("1"),
				},
			}

			pod2 := &corev1.Pod{}
			pod2.Name = "pod2"
			pod2.Spec.NodeName = "node2"

			pod3 := &corev1.Pod{}
			pod3.Name = "pod3"
			pod3.Spec.NodeName = "node1"

			pod4 := &corev1.Pod{}
			pod4.Name = "pod4"
			pod4.Spec.NodeName = "node2"
			pod4.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("1"),
				},
			}

			pod5 := &corev1.Pod{}
			pod5.Name = "pod5"
			pod5.Spec.NodeName = "node1"
			pod5.OwnerReferences = []metav1.OwnerReference{
				{
					UID: types.UID("1"),
				},
			}

			pods := []corev1.Pod{*pod1, *pod2, *pod3, *pod4, *pod5}

			nodesAllocatablePods = map[string]int{
				"node1": 0,
				"node2": 0,
				"node3": 0,
			}

			expectedRes := map[string][]corev1.Pod{}
			expectedCheckResults := []rule.CheckResult{
				{
					Status:  rule.Warning,
					Message: "Pod cannot be tested since it is scheduled on a fully allocated node.",
					Target:  rule.NewTarget("name", "pod2", "namespace", "", "kind", "Pod", "node", "node2"),
				},
				{
					Status:  rule.Warning,
					Message: "Pod cannot be tested since it is scheduled on a fully allocated node.",
					Target:  rule.NewTarget("name", "pod3", "namespace", "", "kind", "Pod", "node", "node1"),
				},
				{
					Status:  rule.Warning,
					Message: "Reference group cannot be tested since all pods of the group are scheduled on a fully allocated node.",
					Target:  rule.NewTarget("name", "", "uid", "1", "kind", "referenceGroup"),
				},
			}

			res, checkResult := utils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, rule.Target{})

			Expect(res).To(Equal(expectedRes))
			Expect(checkResult).To(Equal(expectedCheckResults))
		})
	})

	DescribeTable("#TargetWithK8sObject", func(target rule.Target, objectType metav1.TypeMeta, objectMeta metav1.ObjectMeta, expectedTarget rule.Target) {
		result := utils.TargetWithK8sObject(target, objectType, objectMeta)

		Expect(result).To(Equal(expectedTarget))
	},
		Entry("should return correct target",
			rule.NewTarget(), metav1.TypeMeta{Kind: "Namespace"}, metav1.ObjectMeta{Name: "bar"},
			rule.NewTarget("kind", "Namespace", "name", "bar"),
		),
		Entry("should return correct namespaced target",
			rule.NewTarget(), metav1.TypeMeta{Kind: "Pod"}, metav1.ObjectMeta{Name: "foo", Namespace: "bar"},
			rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar"),
		),
		Entry("should return correct target when objects has ownerReferences",
			rule.NewTarget(), metav1.TypeMeta{Kind: "Pod"},
			metav1.ObjectMeta{Name: "foo", Namespace: "bar", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "baz"}}},
			rule.NewTarget("kind", "ReplicaSet", "name", "baz", "namespace", "bar"),
		),
		Entry("should return the first ownerReference",
			rule.NewTarget(), metav1.TypeMeta{Kind: "Pod"},
			metav1.ObjectMeta{Name: "foo", Namespace: "bar", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "baz"}, {Kind: "ReplicaSet", Name: "foo"}}},
			rule.NewTarget("kind", "ReplicaSet", "name", "baz", "namespace", "bar"),
		),
		Entry("should retain original target values",
			rule.NewTarget("foo", "bar"), metav1.TypeMeta{Kind: "Namespace"}, metav1.ObjectMeta{Name: "bar"},
			rule.NewTarget("foo", "bar", "kind", "Namespace", "name", "bar"),
		),
	)

	DescribeTable("#TargetWithPod", func(target rule.Target, objectType metav1.TypeMeta, objectMeta metav1.ObjectMeta, expectedTarget rule.Target) {
		replicaSets := []appsv1.ReplicaSet{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "replicaSet1",
					Namespace: "bar",
					UID:       "1",
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: "Deployment",
							Name: "deployment",
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "replicaSet2",
					Namespace: "bar",
					UID:       "2",
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: "StatefulSet",
							Name: "statefulSet",
						},
					},
				},
			},
		}
		pod := corev1.Pod{
			TypeMeta:   objectType,
			ObjectMeta: objectMeta,
		}
		result := utils.TargetWithPod(target, pod, replicaSets)

		Expect(result).To(Equal(expectedTarget))
	},
		Entry("should return correct Target",
			rule.NewTarget(), metav1.TypeMeta{Kind: "Pod"}, metav1.ObjectMeta{Name: "foo", Namespace: "bar"},
			rule.NewTarget("kind", "Pod", "name", "foo", "namespace", "bar"),
		),
		Entry("should return correct target when objects has ownerReferences",
			rule.NewTarget(), metav1.TypeMeta{Kind: "Pod"},
			metav1.ObjectMeta{Name: "foo", Namespace: "bar", OwnerReferences: []metav1.OwnerReference{{Kind: "DaemonSet", Name: "baz"}}},
			rule.NewTarget("kind", "DaemonSet", "name", "baz", "namespace", "bar"),
		),
		Entry("should return correct target when objects has replicaSet as ownerReference",
			rule.NewTarget(), metav1.TypeMeta{Kind: "Pod"},
			metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "bar",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       "ReplicaSet",
						UID:        "1",
					},
				},
			},
			rule.NewTarget("kind", "Deployment", "name", "deployment", "namespace", "bar"),
		),
		Entry("should return correct target when objects has more than 1 ownerReference",
			rule.NewTarget(), metav1.TypeMeta{Kind: "Pod"},
			metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "bar",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       "Deployment",
					},
					{
						APIVersion: "apps/v1",
						Kind:       "ReplicaSet",
						UID:        "2",
					},
				},
			},
			rule.NewTarget("kind", "StatefulSet", "name", "statefulSet", "namespace", "bar"),
		),
		Entry("should retain original target values",
			rule.NewTarget("foo", "bar"), metav1.TypeMeta{Kind: "Pod"}, metav1.ObjectMeta{Name: "foo", Namespace: "bar"},
			rule.NewTarget("foo", "bar", "kind", "Pod", "name", "foo", "namespace", "bar"),
		),
	)
})
