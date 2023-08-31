// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"context"
	"fmt"
	"strconv"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	kubernetesgardener "github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
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

	Describe("#GetAllPods", func() {
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
			pods, err := utils.GetAllPods(ctx, fakeClient, namespaceDefault, labels.NewSelector(), 2)

			Expect(len(pods)).To(Equal(12))
			Expect(err).To(BeNil())
		})

		It("should return correct number of pods in foo namespace", func() {
			pods, err := utils.GetAllPods(ctx, fakeClient, namespaceFoo, labels.NewSelector(), 2)

			Expect(len(pods)).To(Equal(6))
			Expect(err).To(BeNil())
		})

		It("should return correct number of pods in all namespaces", func() {
			pods, err := utils.GetAllPods(ctx, fakeClient, "", labels.NewSelector(), 2)

			Expect(len(pods)).To(Equal(18))
			Expect(err).To(BeNil())
		})
		It("should return correct number of labeled pods in default namespace", func() {
			pods, err := utils.GetAllPods(ctx, fakeClient, namespaceDefault, labels.SelectorFromSet(labels.Set{"foo": "bar"}), 2)

			Expect(len(pods)).To(Equal(2))
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

	Describe("#GetWorkers", func() {
		var (
			fakeClient client.Client
			ctx        = context.TODO()
			namespace  = "foo"
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetesgardener.SeedScheme).Build()
			for i := 0; i < 6; i++ {
				worker := &extensionsv1alpha1.Worker{
					ObjectMeta: metav1.ObjectMeta{
						Name:      strconv.Itoa(i),
						Namespace: namespace,
					},
				}
				Expect(fakeClient.Create(ctx, worker)).To(Succeed())
			}
		})

		It("should return correct number of workers", func() {
			workers, err := utils.GetWorkers(ctx, fakeClient, namespace, 2)

			Expect(len(workers)).To(Equal(6))
			Expect(err).To(BeNil())
		})
	})

	Describe("#GetPodSecurityPolicies", func() {
		var (
			fakeClient client.Client
			ctx        = context.TODO()
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().Build()
			for i := 0; i < 6; i++ {
				podSecurityPolicy := &policyv1beta1.PodSecurityPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: strconv.Itoa(i),
					},
				}
				Expect(fakeClient.Create(ctx, podSecurityPolicy)).To(Succeed())
			}
		})

		It("should return correct number of podSecurityPolicies", func() {
			podSecurityPolicies, err := utils.GetPodSecurityPolicies(ctx, fakeClient, 2)

			Expect(len(podSecurityPolicies)).To(Equal(6))
			Expect(err).To(BeNil())
		})
	})

	Describe("#GetSingleRunningNodePerWorker", func() {
		var (
			nodes     []corev1.Node
			node      corev1.Node
			workers   []extensionsv1alpha1.Worker
			namespace = "foo"
		)

		BeforeEach(func() {
			workers = []extensionsv1alpha1.Worker{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "worker1",
						Namespace: namespace,
					},
					Spec: extensionsv1alpha1.WorkerSpec{
						Pools: []extensionsv1alpha1.WorkerPool{
							{
								Name: "pool1",
							},
							{
								Name: "pool2",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "worker2",
						Namespace: namespace,
					},
					Spec: extensionsv1alpha1.WorkerSpec{
						Pools: []extensionsv1alpha1.WorkerPool{
							{
								Name: "pool3",
							},
						},
					},
				},
			}
			node = corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{},
				},
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{},
				},
			}
			nodes = []corev1.Node{}
		})

		It("should return nil or empty when nodes not found or not running", func() {
			pool1Node := node.DeepCopy()
			pool1Node.ObjectMeta.Name = "pool1Node"
			pool1Node.Labels["worker.gardener.cloud/pool"] = "pool1"
			pool1Node.Status.Conditions = []corev1.NodeCondition{
				{
					Type:   corev1.NodeReady,
					Status: corev1.ConditionFalse,
				},
			}
			nodes = append(nodes, *pool1Node)
			singleNodePerWorker := utils.GetSingleRunningNodePerWorker(workers, nodes)

			Expect(singleNodePerWorker).To(Equal(map[string]utils.ReadyNode{
				"pool1": {
					Node:  nil,
					Ready: false,
				},
			}))
		})

		It("should return correct nodes map", func() {
			pool1Node := node.DeepCopy()
			pool1Node.ObjectMeta.Name = "pool1Node"
			pool1Node.Labels["worker.gardener.cloud/pool"] = "pool1"
			pool1Node.Status.Conditions = []corev1.NodeCondition{
				{
					Type:   corev1.NodeReady,
					Status: corev1.ConditionTrue,
				},
			}

			pool1Node2 := node.DeepCopy()
			pool1Node2.ObjectMeta.Name = "pool1Node2"
			pool1Node2.Labels["worker.gardener.cloud/pool"] = "pool1"
			pool1Node2.Status.Conditions = []corev1.NodeCondition{
				{
					Type:   corev1.NodeReady,
					Status: corev1.ConditionTrue,
				},
			}

			pool2Node := node.DeepCopy()
			pool2Node.ObjectMeta.Name = "pool2Node"
			pool2Node.Labels["worker.gardener.cloud/pool"] = "pool2"
			pool2Node.Status.Conditions = []corev1.NodeCondition{
				{
					Type:   corev1.NodeMemoryPressure,
					Status: corev1.ConditionTrue,
				},
				{
					Type:   corev1.NodeReady,
					Status: corev1.ConditionTrue,
				},
			}

			pool3Node := node.DeepCopy()
			pool3Node.ObjectMeta.Name = "pool3Node"
			pool3Node.Labels["worker.gardener.cloud/pool"] = "pool3"
			pool3Node.Status.Conditions = []corev1.NodeCondition{
				{
					Type:   corev1.NodeDiskPressure,
					Status: corev1.ConditionTrue,
				},
			}

			nodes = append(nodes, *pool1Node, *pool1Node2, *pool2Node, *pool3Node)

			singleNodePerWorker := utils.GetSingleRunningNodePerWorker(workers, nodes)

			Expect(singleNodePerWorker).To(Equal(map[string]utils.ReadyNode{
				"pool1": {
					Node:  pool1Node,
					Ready: true,
				},
				"pool2": {
					Node:  pool2Node,
					Ready: true,
				},
				"pool3": {
					Node:  nil,
					Ready: false,
				},
			}))
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
			[]string{"--flag1=value1", "--flag2=value2", "--flag1 value3", "--flag1foo=value4", "--flag1", "--barflag1=value6"},
			"flag1",
			[]string{"value1", "value3", ""}),
		Entry("should correctly find values for flag starts with -",
			[]string{"-flag1=value1", "-flag2=value2", "-flag1 value3", "-flag1foo=value4", "-flag1", "-barflag1=value6"},
			"flag1",
			[]string{"value1", "value3", ""}),
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
			[]string{}),
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
				deploymentName, containerName, namespace, "foo5", []string{}, BeNil()),
			Entry("should return error when the deployment is missing",
				"test", containerName, namespace, "foo", []string{}, MatchError("deployments.apps \"test\" not found")),
			Entry("should return error when the container is missing",
				deploymentName, "test", namespace, "foo", []string{}, MatchError("deployment: foo does not contain container: test")),
		)

	})

	DescribeTable("#EqualSets",
		func(s1, s2 []string, expectedResult bool) {
			result := utils.EqualSets(s1, s2)

			Expect(result).To(Equal(expectedResult))
		},
		Entry("should return true when s1 and s2 have same elements ordered",
			[]string{"foo", "bar"}, []string{"foo", "bar"}, true),
		Entry("should return true when s1 and s2 have same elements not ordered",
			[]string{"bar", "foo"}, []string{"foo", "bar"}, true),
		Entry("should return false when s1 and s2 have different elements",
			[]string{"foo", "bar"}, []string{"foo", "bar", "foo-bar"}, false),
	)

	DescribeTable("#Subset",
		func(s1, s2 []string, expectedResult bool) {
			result := utils.Subset(s1, s2)

			Expect(result).To(Equal(expectedResult))
		},
		Entry("should return true when s1 is empty",
			[]string{}, []string{"foo", "bar"}, true),
		Entry("should return true when s1 is a subset of s2",
			[]string{"bar", "foo"}, []string{"foo", "bar", "foo-bar"}, true),
		Entry("should return false when s1 is not a subset of s2",
			[]string{"foo", "foo-bar"}, []string{"foo", "bar", "test"}, false),
		Entry("should return false when s1 has more elements than s2",
			[]string{"foo", "bar", "foo-bar"}, []string{"foo", "bar"}, false),
	)

	Describe("#MatchFilePermissionsAndOwnersCases", func() {
		var (
			target = gardener.NewTarget()
		)
		DescribeTable("#MatchCases",
			func(filePermissions, fileOwnerUser, fileOwnerGroup, fileName string, expectedFilePermissionsMax string, expectedFileOwnerUsers, expectedFileOwnerGroups []string, target gardener.Target, expectedResults []rule.CheckResult) {
				result := utils.MatchFilePermissionsAndOwnersCases(filePermissions, fileOwnerUser, fileOwnerGroup, fileName, expectedFilePermissionsMax, expectedFileOwnerUsers, expectedFileOwnerGroups, target)

				Expect(result).To(Equal(expectedResults))
			},
			Entry("should return passed when all checks pass",
				"600", "0", "2000", "/foo/bar/file.txt", "644", []string{"0"}, []string{"0", "2000"}, target,
				[]rule.CheckResult{
					rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("details", "fileName: /foo/bar/file.txt, permissions: 600, ownerUser: 0, ownerGroup: 2000")),
				}),
			Entry("should return failed results when all checks fail",
				"700", "1000", "2000", "/foo/bar/file.txt", "644", []string{"0"}, []string{"0", "1000"}, target,
				[]rule.CheckResult{

					rule.FailedCheckResult("File has too wide permissions", gardener.NewTarget("details", "fileName: /foo/bar/file.txt, permissions: 700, expectedPermissionsMax: 644")),
					rule.FailedCheckResult("File has unexpected owner user", gardener.NewTarget("details", "fileName: /foo/bar/file.txt, ownerUser: 1000, expectedOwnerUsers: [0]")),
					rule.FailedCheckResult("File has unexpected owner group", gardener.NewTarget("details", "fileName: /foo/bar/file.txt, ownerGroup: 2000, expectedOwnerGroups: [0 1000]")),
				}),
			Entry("should not check owners when expected slices are empty",
				"664", "1000", "2000", "/foo/bar/file.txt", "644", []string{}, []string{}, target,
				[]rule.CheckResult{
					rule.FailedCheckResult("File has too wide permissions", gardener.NewTarget("details", "fileName: /foo/bar/file.txt, permissions: 664, expectedPermissionsMax: 644")),
				}),
		)
	})
})

const (
	kubeletConfig = `maxPods: 111
readOnlyPort: 222
`
)
