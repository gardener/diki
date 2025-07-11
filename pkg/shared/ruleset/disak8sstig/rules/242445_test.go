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
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#242445", func() {
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
		mountsMulty = `[
  {
    "destination": "/destination",
    "source": "/destination"
  },
  {
    "destination": "/destination",
    "source": "/destination"
  }
]`
		emptyMounts       = `[]`
		compliantStats    = "644\t0\t0\tregular file\t/destination/file1.crt\n400\t0\t0\tregular file\t/destination/bar/file2.key\n"
		compliantStats2   = "600\t0\t0\tregular file\t/destination/file3.key\n600\t0\t0\tregular file\t/destination/bar/file4.txt\n"
		nonCompliantStats = "664\t0\t1000\tregular file\t/destination/file1.key\n700\t2000\t0\tregular file\t/destination/bar/file2.key\n"
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
		etcdMainPod.Labels["app.kubernetes.io/part-of"] = "etcd-main"

		etcdEventsPod = plainPod.DeepCopy()
		etcdEventsPod.Name = "etcd-events"
		etcdEventsPod.Labels["name"] = "etcd"
		etcdEventsPod.Labels["app.kubernetes.io/part-of"] = "etcd-events"

		fooPod = plainPod.DeepCopy()
		fooPod.Name = "foo"

		dikiPod = plainPod.DeepCopy()
		dikiPod.Name = fmt.Sprintf("diki-%s-%s", rules.ID242445, "aaaaaaaaaa")
		dikiPod.Namespace = "kube-system"
		dikiPod.Labels = map[string]string{}
	})

	It("should fail when etcd pods cannot be found", func() {
		Expect(fakeClient.Create(ctx, Node)).To(Succeed())
		Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())
		fakePodContext = fakepod.NewFakeSimplePodContext([][]string{}, [][]error{})
		r := &rules.Rule242445{
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

	DescribeTable("Run cases",
		func(options *option.FileOwnerOptions, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			Expect(fakeClient.Create(ctx, Node)).To(Succeed())
			Expect(fakeClient.Create(ctx, etcdMainPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, etcdEventsPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod)).To(Succeed())

			fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &rules.Rule242445{
				Logger:             testLogger,
				InstanceID:         instanceID,
				Client:             fakeClient,
				Namespace:          Namespace,
				PodContext:         fakePodContext,
				Options:            options,
				ETCDMainSelector:   mainSelector,
				ETCDEventsSelector: eventsSelector,
			}

			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},
		Entry("should return passed checkResults when files have expected permissions", nil,
			[][]string{{mounts, compliantStats, mounts, compliantStats2}},
			[][]error{{nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/file1.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/bar/file2.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/file3.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/bar/file4.txt, ownerUser: 0, ownerGroup: 0")),
			}),
		Entry("should return failed checkResults when files have too wide permissions", nil,
			[][]string{{mounts, nonCompliantStats, emptyMounts}},
			[][]error{{nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/file1.key, ownerGroup: 1000, expectedOwnerGroups: [0]")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/bar/file2.key, ownerUser: 2000, expectedOwnerUsers: [0]")),
			}),
		Entry("should return correct checkResults when options are used", &option.FileOwnerOptions{
			ExpectedFileOwner: option.ExpectedOwner{
				Users:  []string{"0", "2000"},
				Groups: []string{"0", "1000"},
			},
		},
			[][]string{{mounts, nonCompliantStats, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/file1.key, ownerUser: 0, ownerGroup: 1000")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/bar/file2.key, ownerUser: 2000, ownerGroup: 0")),
			}),
		Entry("should correctly return errored checkResults when commands error", nil,
			[][]string{{mounts, mounts, compliantStats2}},
			[][]error{{errors.New("foo"), nil, errors.New("bar")}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242445-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242445-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
			}),
		Entry("should check files when GetMountedFilesStats errors", nil,
			[][]string{{mountsMulty, compliantStats, emptyMounts, emptyMounts, emptyMounts, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, errors.New("bar"), nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242445-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/file1.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/bar/file2.key, ownerUser: 0, ownerGroup: 0")),
			}),
		Entry("should correctly return all checkResults when commands error", nil,
			[][]string{{mounts, mounts, compliantStats2}},
			[][]error{{errors.New("foo"), nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242445-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/file3.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/bar/file4.txt, ownerUser: 0, ownerGroup: 0")),
			}),
	)
})
