// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11_test

import (
	"context"
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ = Describe("#242459", func() {
	const (
		mounts = `[
  {
    "destination": "/destination",
    "source": "/destination"
  }, 
  {
    "destination": "/foo",
    "source": "/source"
  },
  {
    "destination": "/bar",
    "source": "/source"
  }
]`
		emptyMounts       = `[]`
		compliantStats    = "600\t0\t0\tregular file\t/destination/file1.txt\n644\t0\t65532\tregular file\t/destination/bar/file2.txt"
		compliantStats2   = "640\t0\t0\tregular file\t/destination/file3.txt\n400\t1000\t0\tregular file\t/destination/bar/file4.txt\n"
		nonCompliantStats = "654\t0\t0\tregular file\t/destination/file1.key\n744\t0\t0\tregular file\t/destination/bar/file2.key\n"
	)
	var (
		instanceID     = "1"
		fakeClient     client.Client
		Namespace      = "foo"
		fakePodContext pod.PodContext
		nodeName       = "node01"
		Node           *corev1.Node
		plainPod       *corev1.Pod
		etcdMainPod    *corev1.Pod
		etcdEventsPod  *corev1.Pod
		fooPod         *corev1.Pod
		dikiPod        *corev1.Pod
		ctx            = context.TODO()
	)

	BeforeEach(func() {
		v1r11.Generator = &FakeRandString{CurrentChar: 'a'}
		fakeClient = fakeclient.NewClientBuilder().Build()

		Node = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{
					"pods": resource.MustParse("100.0"),
				},
			},
		}

		plainPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Labels:    map[string]string{},
				Namespace: "foo",
			},
			Spec: corev1.PodSpec{
				NodeName: nodeName,
				Containers: []corev1.Container{
					{
						Name: "test",
						VolumeMounts: []corev1.VolumeMount{
							{
								MountPath: "/destination",
							},
							{
								Name:      "bar",
								MountPath: "/bar",
							},
							{
								MountPath: "/destination/etcd/data",
							},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "bar",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/lib/modules",
							},
						},
					},
				},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:        "test",
						ContainerID: "containerd://bar",
					},
				},
			},
		}

		etcdMainPod = plainPod.DeepCopy()
		etcdMainPod.Name = "1-pod"
		etcdMainPod.Labels["name"] = "etcd"
		etcdMainPod.Labels["instance"] = "etcd-main"

		etcdEventsPod = plainPod.DeepCopy()
		etcdEventsPod.Name = "etcd-events"
		etcdEventsPod.Labels["name"] = "etcd"
		etcdEventsPod.Labels["instance"] = "etcd-events"

		fooPod = plainPod.DeepCopy()
		fooPod.Name = "foo"

		dikiPod = plainPod.DeepCopy()
		dikiPod.Name = fmt.Sprintf("diki-%s-%s", v1r11.ID242459, "aaaaaaaaaa")
		dikiPod.Namespace = "kube-system"
		dikiPod.Labels = map[string]string{}
	})

	It("should fail when etcd pods cannot be found", func() {
		Expect(fakeClient.Create(ctx, Node)).To(Succeed())
		Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())

		fakePodContext = fakepod.NewFakeSimplePodContext([][]string{}, [][]error{})
		r := &v1r11.Rule242459{
			Logger:             testLogger,
			InstanceID:         instanceID,
			Client:             fakeClient,
			Namespace:          Namespace,
			PodContext:         fakePodContext,
			ETCDMainInstance:   "etcd-main",
			ETCDEventsInstance: "etcd-events",
		}

		ruleResult, err := r.Run(ctx)

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			rule.FailedCheckResult("etcd-main pods not found!", rule.NewTarget()),
			rule.FailedCheckResult("etcd-events pods not found!", rule.NewTarget()),
		}))
	})

	DescribeTable("Run cases",
		func(executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			Expect(fakeClient.Create(ctx, Node)).To(Succeed())
			Expect(fakeClient.Create(ctx, etcdMainPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, etcdEventsPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod)).To(Succeed())

			fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &v1r11.Rule242459{
				Logger:             testLogger,
				InstanceID:         instanceID,
				Client:             fakeClient,
				Namespace:          Namespace,
				PodContext:         fakePodContext,
				ETCDMainInstance:   "etcd-main",
				ETCDEventsInstance: "etcd-events",
			}

			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},
		Entry("should return passed checkResults when files have expected permissions",
			[][]string{{mounts, compliantStats, mounts, compliantStats2}},
			[][]error{{nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.txt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.txt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file3.txt, permissions: 640")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file4.txt, permissions: 400")),
			}),
		Entry("should return failed checkResults when files have too wide permissions",
			[][]string{{mounts, nonCompliantStats, emptyMounts}},
			[][]error{{nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.key, permissions: 654, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.key, permissions: 744, expectedPermissionsMax: 644")),
			}),
		Entry("should correctly return errored checkResults when commands error",
			[][]string{{mounts, mounts, compliantStats2}},
			[][]error{{errors.New("foo"), nil, errors.New("bar")}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242459-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242459-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
			}),
		Entry("should correctly return all checkResults when commands error",
			[][]string{{mounts, mounts, compliantStats2}},
			[][]error{{errors.New("foo"), nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242459-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file3.txt, permissions: 640")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file4.txt, permissions: 400")),
			}),
	)
})
