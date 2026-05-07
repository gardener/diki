// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package pod_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	fakestrgen "github.com/gardener/diki/pkg/internal/stringgen/fake"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

func makeNode(name string, labels map[string]string) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				"pods": resource.MustParse("100"),
			},
		},
	}
}

var _ = Describe("PodWorkerPool", func() {
	var (
		pool    *pod.PodWorkerPool
		fakeCtx *fakepod.FakeSimplePodContext
	)

	BeforeEach(func() {
		fakeCtx = fakepod.NewFakeSimplePodContext(
			[][]string{{"result1"}, {"result2"}, {"result3"}},
			[][]error{{nil}, {nil}, {nil}},
		)
		nodeConstructorFn := func(nodeName string) func() *corev1.Pod {
			return pod.NewPrivilegedPod("", "kube-system", "img", nodeName, nil)
		}
		pool = pod.NewPodWorkerPool(fakeCtx, kubeutils.SelectNodes, kubeutils.SelectPodOfReferenceGroup, nodeConstructorFn)
		pool.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
	})

	Describe("#Create", func() {
		It("should create a pod and return a NamedPodExecutor", func() {
			executor, err := pool.Create(context.TODO(), pod.NewPrivilegedPod("pod1", "kube-system", "img", "node1", nil))

			Expect(err).NotTo(HaveOccurred())
			named, ok := executor.(*pod.NamedPodExecutor)
			Expect(ok).To(BeTrue())
			// Pool overrides the name with FNV hash of node name + random suffix.
			Expect(named.PodName).To(Equal("diki-pool-0f4e2874-aaaaaaaaaa"))
			Expect(named.PodNamespace).To(Equal("kube-system"))
		})

		It("should reuse the executor for the same node", func() {
			exec1, err := pool.Create(context.TODO(), pod.NewPrivilegedPod("pod1", "kube-system", "img", "node1", nil))
			Expect(err).NotTo(HaveOccurred())

			exec2, err := pool.Create(context.TODO(), pod.NewPrivilegedPod("pod2", "kube-system", "img", "node1", nil))
			Expect(err).NotTo(HaveOccurred())

			named1 := exec1.(*pod.NamedPodExecutor)
			named2 := exec2.(*pod.NamedPodExecutor)
			Expect(named1.PodExecutor).To(BeIdenticalTo(named2.PodExecutor))
			Expect(named2.PodName).To(Equal("diki-pool-0f4e2874-aaaaaaaaaa"))
		})

		It("should create separate pods for different nodes", func() {
			exec1, err := pool.Create(context.TODO(), pod.NewPrivilegedPod("pod1", "kube-system", "img", "node1", nil))
			Expect(err).NotTo(HaveOccurred())

			exec2, err := pool.Create(context.TODO(), pod.NewPrivilegedPod("pod2", "kube-system", "img", "node2", nil))
			Expect(err).NotTo(HaveOccurred())

			named1 := exec1.(*pod.NamedPodExecutor)
			named2 := exec2.(*pod.NamedPodExecutor)
			Expect(named1.PodExecutor).NotTo(BeIdenticalTo(named2.PodExecutor))
		})

		It("should pool pods with empty node name", func() {
			exec1, err := pool.Create(context.TODO(), pod.NewPrivilegedPod("pod1", "kube-system", "img", "", nil))
			Expect(err).NotTo(HaveOccurred())

			exec2, err := pool.Create(context.TODO(), pod.NewPrivilegedPod("pod2", "kube-system", "img", "", nil))
			Expect(err).NotTo(HaveOccurred())

			named1 := exec1.(*pod.NamedPodExecutor)
			named2 := exec2.(*pod.NamedPodExecutor)
			Expect(named1.PodExecutor).To(BeIdenticalTo(named2.PodExecutor))
		})
	})

	Describe("#Delete", func() {
		It("should be a no-op", func() {
			err := pool.Delete(context.TODO(), "pod1", "kube-system")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("#SelectNodes", func() {
		It("should select nodes and eagerly create pods", func() {
			node1 := makeNode("node1", map[string]string{})
			node2 := makeNode("node2", map[string]string{})
			allocatable := map[string]int{"node1": 100, "node2": 100}

			selected, checks := pool.SelectNodes(context.TODO(), []corev1.Node{node1, node2}, allocatable, nil)

			Expect(checks).To(BeEmpty())
			Expect(selected).To(ConsistOf(node1, node2))

			// Pods should have been eagerly created — Create returns a cache hit.
			exec, err := pool.Create(context.TODO(), pod.NewPrivilegedPod("other-name", "kube-system", "img", "node1", nil))
			Expect(err).NotTo(HaveOccurred())
			named := exec.(*pod.NamedPodExecutor)
			Expect(named.PodName).To(Equal("diki-pool-0f4e2874-aaaaaaaaaa"))
		})

		It("should select one node per label group", func() {
			node1 := makeNode("node1", map[string]string{"pool": "a"})
			node2 := makeNode("node2", map[string]string{"pool": "a"})
			node3 := makeNode("node3", map[string]string{"pool": "b"})
			allocatable := map[string]int{"node1": 100, "node2": 100, "node3": 100}

			selected, checks := pool.SelectNodes(context.TODO(), []corev1.Node{node1, node2, node3}, allocatable, []string{"pool"})

			Expect(checks).To(BeEmpty())
			Expect(selected).To(HaveLen(2))
			Expect(selected).To(ContainElement(node3))
		})

		It("should prefer nodes that already have a pooled executor", func() {
			// Pre-seed pool with executor on node2.
			_, err := pool.Create(context.TODO(), pod.NewPrivilegedPod("seed-pod", "kube-system", "img", "node2", nil))
			Expect(err).NotTo(HaveOccurred())

			node1 := makeNode("node1", map[string]string{})
			node2 := makeNode("node2", map[string]string{})
			// node1 has 0 allocatable (full), node2 has 0 allocatable (full).
			// Without pool boost, neither is selectable.
			// With pool boost, node2 gets 1<<20 and becomes selectable.
			allocatable := map[string]int{"node1": 0, "node2": 0}

			selected, _ := pool.SelectNodes(context.TODO(), []corev1.Node{node1, node2}, allocatable, nil)

			Expect(selected).To(ConsistOf(node2))
		})

		It("should emit a warning for nodes missing the label", func() {
			node1 := makeNode("node1", map[string]string{"pool": "a"})
			node2 := makeNode("node2", map[string]string{})
			allocatable := map[string]int{"node1": 100, "node2": 100}

			selected, checks := pool.SelectNodes(context.TODO(), []corev1.Node{node1, node2}, allocatable, []string{"pool"})

			Expect(selected).To(ConsistOf(node1))
			Expect(checks).To(ConsistOf(
				rule.WarningCheckResult("Node is missing a label", rule.NewTarget("kind", "Node", "name", "node2", "label", "pool")),
			))
		})
	})

	Describe("#SelectPodOfReferenceGroup", func() {
		It("should select pods and eagerly create exec pods on selected nodes", func() {
			targetPod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			}
			allocatable := map[string]int{"node1": 100}

			grouped, checks := pool.SelectPodOfReferenceGroup(context.TODO(), []corev1.Pod{targetPod}, nil, allocatable, rule.NewTarget())

			Expect(checks).To(BeEmpty())
			Expect(grouped).To(HaveKey("node1"))

			// Exec pod should have been eagerly created.
			exec, err := pool.Create(context.TODO(), pod.NewPrivilegedPod("other", "kube-system", "img", "node1", nil))
			Expect(err).NotTo(HaveOccurred())
			named := exec.(*pod.NamedPodExecutor)
			Expect(named.PodName).To(Equal("diki-pool-0f4e2874-aaaaaaaaaa"))
		})
	})

	Describe("#CleanupAll", func() {
		It("should delete all pooled pods via the underlying PodContext", func() {
			_, err := pool.Create(context.TODO(), pod.NewPrivilegedPod("pod1", "kube-system", "img", "node1", nil))
			Expect(err).NotTo(HaveOccurred())
			_, err = pool.Create(context.TODO(), pod.NewPrivilegedPod("pod2", "kube-system", "img", "node2", nil))
			Expect(err).NotTo(HaveOccurred())

			err = pool.CleanupAll(context.TODO())
			Expect(err).NotTo(HaveOccurred())
		})

		It("should work with an empty pool", func() {
			err := pool.CleanupAll(context.TODO())
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("PodContext interface", func() {
		It("should satisfy the PodContext interface", func() {
			var _ pod.PodContext = pool
		})
	})

	Describe("NamedPodExecutor", func() {
		It("should delegate Execute to the wrapped PodExecutor", func() {
			executor, err := pool.Create(context.TODO(), pod.NewPrivilegedPod("pod1", "kube-system", "img", "node1", nil))
			Expect(err).NotTo(HaveOccurred())

			result, err := executor.Execute(context.TODO(), "cmd", "shell")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal("result1"))
		})
	})
})
