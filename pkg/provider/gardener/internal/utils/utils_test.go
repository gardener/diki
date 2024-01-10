// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"context"
	"strconv"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	kubernetesgardener "github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("utils", func() {

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

	Describe("#GetSingleAllocatableNodePerWorker", func() {
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
			nodesAllocatablePods := map[string]int{
				"pool1Node": 1,
			}

			singleNodePerWorker := utils.GetSingleAllocatableNodePerWorker(workers, nodes, nodesAllocatablePods)

			Expect(singleNodePerWorker).To(Equal(map[string]utils.AllocatableNode{
				"pool1": {
					Node:        nil,
					Allocatable: false,
				},
			}))
		})

		It("should return nil when nodes do not have allocatable spots", func() {
			pool1Node := node.DeepCopy()
			pool1Node.ObjectMeta.Name = "pool1Node"
			pool1Node.Labels["worker.gardener.cloud/pool"] = "pool1"
			pool1Node.Status.Conditions = []corev1.NodeCondition{
				{
					Type:   corev1.NodeReady,
					Status: corev1.ConditionTrue,
				},
			}
			nodes = append(nodes, *pool1Node)
			nodesAllocatablePods := map[string]int{
				"pool1Node": 0,
			}

			singleNodePerWorker := utils.GetSingleAllocatableNodePerWorker(workers, nodes, nodesAllocatablePods)

			Expect(singleNodePerWorker).To(Equal(map[string]utils.AllocatableNode{
				"pool1": {
					Node:        nil,
					Allocatable: false,
				},
			}))
		})

		It("should prioritize nodes with more allocatable spots", func() {
			pool1Node1 := node.DeepCopy()
			pool1Node1.ObjectMeta.Name = "pool1Node2"
			pool1Node1.Labels["worker.gardener.cloud/pool"] = "pool1"
			pool1Node1.Status.Conditions = []corev1.NodeCondition{
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
			nodes = append(nodes, *pool1Node1, *pool1Node2)
			nodesAllocatablePods := map[string]int{
				"pool1Node1": 1,
				"pool1Node2": 5,
			}

			singleNodePerWorker := utils.GetSingleAllocatableNodePerWorker(workers, nodes, nodesAllocatablePods)

			Expect(singleNodePerWorker).To(Equal(map[string]utils.AllocatableNode{
				"pool1": {
					Node:        pool1Node2,
					Allocatable: true,
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
			nodesAllocatablePods := map[string]int{
				"pool1Node":  1,
				"pool1Node2": 1,
				"pool2Node":  1,
				"pool3Node":  1,
			}

			singleNodePerWorker := utils.GetSingleAllocatableNodePerWorker(workers, nodes, nodesAllocatablePods)

			Expect(singleNodePerWorker).To(Equal(map[string]utils.AllocatableNode{
				"pool1": {
					Node:        pool1Node,
					Allocatable: true,
				},
				"pool2": {
					Node:        pool2Node,
					Allocatable: true,
				},
				"pool3": {
					Node:        nil,
					Allocatable: false,
				},
			}))
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

	DescribeTable("#ExceedFilePermissions",
		func(filePermissions, filePermissionsMax string, expectedResult bool, errorMatcher gomegatypes.GomegaMatcher) {
			result, err := utils.ExceedFilePermissions(filePermissions, filePermissionsMax)

			Expect(result).To(Equal(expectedResult))
			Expect(err).To(errorMatcher)
		},
		Entry("should return false when filePermissions do not exceed filePermissionsMax",
			"0600", "0644", false, BeNil()),
		Entry("should return false when filePermissions equal filePermissionsMax",
			"0644", "0644", false, BeNil()),
		Entry("should return true when filePermissions exceed filePermissionsMax by user permissions",
			"0700", "0644", true, BeNil()),
		Entry("should return true when filePermissions exceed filePermissionsMax by group permissions",
			"0460", "0644", true, BeNil()),
		Entry("should return true when filePermissions exceed filePermissionsMax by other permissions",
			"0406", "0644", true, BeNil()),
	)

	Describe("#MatchFileOwnersCases", func() {
		var (
			target = rule.NewTarget()
		)
		DescribeTable("#MatchCases",
			func(fileOwnerUser, fileOwnerGroup, fileName string, expectedFileOwnerUsers, expectedFileOwnerGroups []string, target rule.Target, expectedResults []rule.CheckResult) {
				result := utils.MatchFileOwnersCases(fileOwnerUser, fileOwnerGroup, fileName, expectedFileOwnerUsers, expectedFileOwnerGroups, target)

				Expect(result).To(Equal(expectedResults))
			},
			Entry("should return passed when all checks pass",
				"0", "2000", "/foo/bar/file.txt", []string{"0"}, []string{"0", "2000"}, target,
				[]rule.CheckResult{
					rule.PassedCheckResult("File has expected owners", rule.NewTarget("details", "fileName: /foo/bar/file.txt, ownerUser: 0, ownerGroup: 2000")),
				}),
			Entry("should return failed results when all checks fail",
				"1000", "2000", "/foo/bar/file.txt", []string{"0"}, []string{"0", "1000"}, target,
				[]rule.CheckResult{

					rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("details", "fileName: /foo/bar/file.txt, ownerUser: 1000, expectedOwnerUsers: [0]")),
					rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("details", "fileName: /foo/bar/file.txt, ownerGroup: 2000, expectedOwnerGroups: [0 1000]")),
				}),
			Entry("should return failed when expected owners are empty",
				"1000", "2000", "/foo/bar/file.txt", []string{}, []string{}, target,
				[]rule.CheckResult{
					rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("details", "fileName: /foo/bar/file.txt, ownerUser: 1000, expectedOwnerUsers: []")),
					rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("details", "fileName: /foo/bar/file.txt, ownerGroup: 2000, expectedOwnerGroups: []")),
				}),
		)
	})

	Describe("#MatchFilePermissionsAndOwnersCases", func() {
		var (
			target = rule.NewTarget()
		)
		DescribeTable("#MatchCases",
			func(filePermissions, fileOwnerUser, fileOwnerGroup, fileName string, expectedFilePermissionsMax string, expectedFileOwnerUsers, expectedFileOwnerGroups []string, target rule.Target, expectedResults []rule.CheckResult) {
				result := utils.MatchFilePermissionsAndOwnersCases(filePermissions, fileOwnerUser, fileOwnerGroup, fileName, expectedFilePermissionsMax, expectedFileOwnerUsers, expectedFileOwnerGroups, target)

				Expect(result).To(Equal(expectedResults))
			},
			Entry("should return passed when all checks pass",
				"600", "0", "2000", "/foo/bar/file.txt", "644", []string{"0"}, []string{"0", "2000"}, target,
				[]rule.CheckResult{
					rule.PassedCheckResult("File has expected permissions and expected owner", rule.NewTarget("details", "fileName: /foo/bar/file.txt, permissions: 600, ownerUser: 0, ownerGroup: 2000")),
				}),
			Entry("should return failed results when all checks fail",
				"466", "1000", "2000", "/foo/bar/file.txt", "644", []string{"0"}, []string{"0", "1000"}, target,
				[]rule.CheckResult{

					rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("details", "fileName: /foo/bar/file.txt, permissions: 466, expectedPermissionsMax: 644")),
					rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("details", "fileName: /foo/bar/file.txt, ownerUser: 1000, expectedOwnerUsers: [0]")),
					rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("details", "fileName: /foo/bar/file.txt, ownerGroup: 2000, expectedOwnerGroups: [0 1000]")),
				}),
			Entry("should not check owners when expected slices are empty",
				"664", "1000", "2000", "/foo/bar/file.txt", "644", []string{}, []string{}, target,
				[]rule.CheckResult{
					rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("details", "fileName: /foo/bar/file.txt, permissions: 664, expectedPermissionsMax: 644")),
				}),
		)
	})
})
