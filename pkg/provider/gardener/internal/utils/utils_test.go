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
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/gardener"
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

	DescribeTable("#MatchLabels",
		func(m1, m2 map[string]string, expectedResult bool) {
			result := utils.MatchLabels(m1, m2)

			Expect(result).To(Equal(expectedResult))
		},
		Entry("should return true when m1 contains all keys and values of m2",
			map[string]string{"foo": "bar", "key1": "value1", "key2": "value2"},
			map[string]string{"key1": "value1", "key2": "value2"}, true),
		Entry("should return false when m1 does not contain all keys and values of m2",
			map[string]string{"key1": "value1", "key2": "value2"},
			map[string]string{"key1": "value1", "foo": "bar"}, false),
		Entry("should return false when m1 is nil",
			nil, map[string]string{"key1": "value1", "foo": "bar"}, false),
		Entry("should return false when m2 is nil",
			map[string]string{"key1": "value1", "foo": "bar"}, nil, false),
	)

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
				"466", "1000", "2000", "/foo/bar/file.txt", "644", []string{"0"}, []string{"0", "1000"}, target,
				[]rule.CheckResult{

					rule.FailedCheckResult("File has too wide permissions", gardener.NewTarget("details", "fileName: /foo/bar/file.txt, permissions: 466, expectedPermissionsMax: 644")),
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

	Describe("#GetNodesAllocatablePods", func() {
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

			res := utils.GetNodesAllocatablePods(pods, nodes)

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

			res := utils.GetNodesAllocatablePods(pods, nodes)

			Expect(res).To(Equal(expectedRes))
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

			res, checkResult := utils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, gardener.Target{})

			Expect(res).To(Equal(expectedRes))
			Expect(checkResult).To(Equal([]rule.CheckResult{}))
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

			res, checkResult := utils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, gardener.Target{})

			Expect(res).To(Equal(expectedRes))
			Expect(checkResult).To(Equal([]rule.CheckResult{}))
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

			res, checkResult := utils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, gardener.Target{})

			Expect(res).To(Equal(expectedRes))
			Expect(checkResult).To(Equal([]rule.CheckResult{}))
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

			res, checkResult := utils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, gardener.Target{})

			Expect(res).To(Equal(expectedRes))
			Expect(checkResult).To(Equal([]rule.CheckResult{}))
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
					Target:  gardener.NewTarget("name", "pod1", "namespace", "", "kind", "pod"),
				},
			}

			res, checkResult := utils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, gardener.Target{})

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
					Message: "Pod cannon be tested, since it is scheduled on a fully allocated node.",
					Target:  gardener.NewTarget("name", "pod2", "namespace", "", "kind", "pod", "node", "node2"),
				},
				{
					Status:  rule.Warning,
					Message: "Pod cannon be tested, since it is scheduled on a fully allocated node.",
					Target:  gardener.NewTarget("name", "pod3", "namespace", "", "kind", "pod", "node", "node1"),
				},
				{
					Status:  rule.Warning,
					Message: "Reference group cannon be tested, since all pods of the group are scheduled on a fully allocated node.",
					Target:  gardener.NewTarget("name", "", "uid", "1", "kind", "referenceGroup"),
				},
			}

			res, checkResult := utils.SelectPodOfReferenceGroup(pods, nodesAllocatablePods, gardener.Target{})

			Expect(res).To(Equal(expectedRes))
			Expect(checkResult).To(Equal(expectedCheckResults))
		})

	})
})
