// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	fakestrgen "github.com/gardener/diki/pkg/internal/stringgen/fake"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#242459", func() {
	const (
		mounts = `[
  {
    "destination": "/var/lib",
    "source": "/source1"
  }, 
  {
    "destination": "/var/etcd/data",
    "source": "/source2"
  },
  {
    "destination": "/bar",
    "source": "/source3"
  }
]`
		mountsMulty = `[
  {
    "destination": "/var/lib",
    "source": "/source1"
  },
  {
    "destination": "/var/lib",
    "source": "/source1"
  }
]`
		emptyMounts           = `[]`
		compliantStats        = "644\t0\t0\tregular file\t/source1/file1.txt\n400\t0\t65532\tregular file\t/source1/bar/file2.txt"
		compliantStats2       = "600\t0\t0\tregular file\t/source1/file3.txt\n640\t1000\t0\tregular file\t/source1/bar/file4.txt\n"
		compliantDataStats    = "660\t0\t0\tregular file\t/source2/file1.txt\n400\t0\t65532\tregular file\t/source2/bar/file2.txt"
		compliantDataStats2   = "600\t0\t0\tregular file\t/source2/file3.txt\n640\t1000\t0\tregular file\t/source2/bar/file4.txt\n"
		nonCompliantStats     = "660\t0\t0\tregular file\t/source1/file1.key\n700\t0\t0\tregular file\t/source1/bar/file2.key\n"
		nonCompliantDataStats = "644\t0\t0\tregular file\t/source2/file1.key\n700\t0\t0\tregular file\t/source2/bar/file2.key\n"
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
		mainSelector   = labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": "etcd-main"})
		eventsSelector = labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": "etcd-events"})
	)

	BeforeEach(func() {
		rules.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
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
								Name:      "lib",
								MountPath: "/var/lib",
							},
							{
								Name:      "data",
								MountPath: "/var/etcd/data",
							},
							{
								MountPath: "/bar/foo",
							},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "lib",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/lib",
							},
						},
					},
					{
						Name: "data",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/etcd/data",
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
		etcdMainPod.Labels["app.kubernetes.io/part-of"] = "etcd-main"

		etcdEventsPod = plainPod.DeepCopy()
		etcdEventsPod.Name = "etcd-events"
		etcdEventsPod.Labels["name"] = "etcd"
		etcdEventsPod.Labels["app.kubernetes.io/part-of"] = "etcd-events"

		fooPod = plainPod.DeepCopy()
		fooPod.Name = "foo"

		dikiPod = plainPod.DeepCopy()
		dikiPod.Name = fmt.Sprintf("diki-%s-%s", rules.ID242459, "aaaaaaaaaa")
		dikiPod.Namespace = "kube-system"
		dikiPod.Labels = map[string]string{}
	})

	It("should fail when etcd pods cannot be found", func() {
		Expect(fakeClient.Create(ctx, Node)).To(Succeed())
		Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())
		fakePodContext = fakepod.NewFakeSimplePodContext([][]string{}, [][]error{})
		r := &rules.Rule242459{
			Logger:             testLogger,
			InstanceID:         instanceID,
			Client:             fakeClient,
			Namespace:          Namespace,
			PodContext:         fakePodContext,
			ETCDMainSelector:   mainSelector,
			ETCDEventsSelector: eventsSelector,
		}

		ruleResult, err := r.Run(ctx)
		target := rule.NewTarget("namespace", r.Namespace)
		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			rule.ErroredCheckResult("pods not found", target.With("selector", mainSelector.String())),
			rule.ErroredCheckResult("pods not found", target.With("selector", eventsSelector.String())),
		}))
	})

	//TODO: Remove these describe table test cases once support for the instance labels is deprecated
	DescribeTable("Run temporary instance label cases",
		func(includeETCDEventsPod bool, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			Expect(fakeClient.Create(ctx, Node)).To(Succeed())

			oldSelectorETCDMainPod := etcdMainPod.DeepCopy()
			delete(oldSelectorETCDMainPod.Labels, "app.kubernetes.io/part-of")
			oldSelectorETCDMainPod.Labels["instance"] = "etcd-main"
			Expect(fakeClient.Create(ctx, oldSelectorETCDMainPod))

			if includeETCDEventsPod {
				oldSelectorETCDEventsPod := etcdEventsPod.DeepCopy()
				delete(oldSelectorETCDEventsPod.Labels, "app.kubernetes.io/part-of")
				oldSelectorETCDEventsPod.Labels["instance"] = "etcd-events"
				Expect(fakeClient.Create(ctx, oldSelectorETCDEventsPod))
			}

			Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod)).To(Succeed())

			fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &rules.Rule242459{
				Logger:             testLogger,
				InstanceID:         instanceID,
				Client:             fakeClient,
				Namespace:          Namespace,
				PodContext:         fakePodContext,
				ETCDMainSelector:   mainSelector,
				ETCDEventsSelector: eventsSelector,
			}

			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},
		Entry("should return passed checkResults from ETCD pods with old labels", true,
			[][]string{{mounts, compliantStats, compliantDataStats, mounts, compliantStats2, compliantDataStats2}},
			[][]error{{nil, nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/file1.txt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/bar/file2.txt, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/file1.txt, permissions: 660")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/bar/file2.txt, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/file3.txt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/bar/file4.txt, permissions: 640")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/file3.txt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/bar/file4.txt, permissions: 640")),
			}),
		Entry("should return correct errored checkResults when old ETCD pods are partially found", false,
			[][]string{{mounts, compliantStats, compliantDataStats}},
			[][]error{{nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("pods not found", rule.NewTarget("selector", "instance=etcd-events", "namespace", "foo")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/file1.txt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/bar/file2.txt, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/file1.txt, permissions: 660")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/bar/file2.txt, permissions: 400")),
			}))

	DescribeTable("Run cases",
		func(executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			Expect(fakeClient.Create(ctx, Node)).To(Succeed())
			Expect(fakeClient.Create(ctx, etcdMainPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, etcdEventsPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod)).To(Succeed())

			fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &rules.Rule242459{
				Logger:             testLogger,
				InstanceID:         instanceID,
				Client:             fakeClient,
				Namespace:          Namespace,
				PodContext:         fakePodContext,
				ETCDMainSelector:   mainSelector,
				ETCDEventsSelector: eventsSelector,
			}

			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
		},
		Entry("should return passed checkResults when files have expected permissions",
			[][]string{{mounts, compliantStats, compliantDataStats, mounts, compliantStats2, compliantDataStats2}},
			[][]error{{nil, nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/file1.txt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/bar/file2.txt, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/file1.txt, permissions: 660")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/bar/file2.txt, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/file3.txt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/bar/file4.txt, permissions: 640")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/file3.txt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/bar/file4.txt, permissions: 640")),
			}),
		Entry("should return failed checkResults when files have too wide permissions",
			[][]string{{mounts, nonCompliantStats, nonCompliantDataStats, emptyMounts}},
			[][]error{{nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/file1.key, permissions: 660, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/bar/file2.key, permissions: 700, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/file1.key, permissions: 644, expectedPermissionsMax: 660")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/bar/file2.key, permissions: 700, expectedPermissionsMax: 660")),
			}),
		Entry("should correctly return errored checkResults when commands error",
			[][]string{{mounts, mounts, compliantStats2, compliantDataStats2}},
			[][]error{{errors.New("foo"), nil, errors.New("bar"), nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242459-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242459-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/file3.txt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/bar/file4.txt, permissions: 640")),
			}),
		Entry("should check files when GetMountedFilesStats errors",
			[][]string{{mountsMulty, compliantStats, compliantStats2, emptyMounts, emptyMounts, emptyMounts, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, errors.New("bar"), nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242459-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/file1.txt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/bar/file2.txt, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/file3.txt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/bar/file4.txt, permissions: 640")),
			}),
		Entry("should correctly return all checkResults when commands error",
			[][]string{{mounts, mounts, compliantStats2, compliantDataStats2}},
			[][]error{{errors.New("foo"), nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242459-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/file3.txt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source1/bar/file4.txt, permissions: 640")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/file3.txt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /source2/bar/file4.txt, permissions: 640")),
			}),
	)
})
