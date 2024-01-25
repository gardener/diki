// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
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

	fakestrgen "github.com/gardener/diki/pkg/internal/stringgen/fake"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var _ = Describe("#RulePodFiles", func() {
	const (
		mounts = `[
  {
    "destination": "/destination",
    "source": "/source"
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
		emptyMounts    = `[]`
		mountsWithETCD = `[
  {
    "destination": "/destination/etcd/data",
    "source": "/source"
  }
]`
		compliantStats = `600 0 0 /destination/file1.txt
644 0 65532 /destination/bar/file2.txt`
		keyFileStats = `640 0 0 /destination/file1.key
644 0 0 /destination/bar/file2.key`
	)

	var (
		instanceID                 = "1"
		fakeClusterClient          client.Client
		fakeControlPlaneClient     client.Client
		controlPlaneNamespace      = "foo"
		fakeClusterPodContext      pod.PodContext
		fakeControlPlanePodContext pod.PodContext
		nodeName                   = "node01"
		plainNode                  *corev1.Node
		controlPlaneNode           *corev1.Node
		clusterNode                *corev1.Node
		plainPod                   *corev1.Pod
		plainControlPlanePod       *corev1.Pod
		etcdMainPod                *corev1.Pod
		etcdEventsPod              *corev1.Pod
		kubeAPIPod                 *corev1.Pod
		kubeSchedulerPod           *corev1.Pod
		kubeControllerManagerPod   *corev1.Pod
		kubeProxyPod               *corev1.Pod
		controlPlaneDikiPod        *corev1.Pod
		plainClusterPod            *corev1.Pod
		clusterPod                 *corev1.Pod
		clusterDikiPod             *corev1.Pod
		ctx                        = context.TODO()
	)

	BeforeEach(func() {
		v1r11.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
		fakeClusterClient = fakeclient.NewClientBuilder().Build()
		fakeControlPlaneClient = fakeclient.NewClientBuilder().Build()

		plainNode = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{
					"pods": resource.MustParse("100.0"),
				},
			},
		}

		controlPlaneNode = plainNode.DeepCopy()
		clusterNode = plainNode.DeepCopy()

		plainPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{},
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

		plainControlPlanePod = plainPod.DeepCopy()
		plainControlPlanePod.Namespace = controlPlaneNamespace
		plainControlPlanePod.Labels["gardener.cloud/role"] = "controlplane"

		etcdMainPod = plainControlPlanePod.DeepCopy()
		etcdMainPod.Name = "1-seed-pod"
		etcdMainPod.Labels["name"] = "etcd"
		etcdMainPod.Labels["instance"] = "etcd-main"

		etcdEventsPod = plainControlPlanePod.DeepCopy()
		etcdEventsPod.Name = "etcd-events"
		etcdEventsPod.Labels["name"] = "etcd"
		etcdEventsPod.Labels["instance"] = "etcd-events"

		kubeAPIPod = plainControlPlanePod.DeepCopy()
		kubeAPIPod.Name = "kube-api"
		kubeAPIPod.Labels["role"] = "apiserver"

		kubeControllerManagerPod = plainControlPlanePod.DeepCopy()
		kubeControllerManagerPod.Name = "kube-controller-manager"
		kubeControllerManagerPod.Labels["role"] = "controller-manager"

		kubeSchedulerPod = plainControlPlanePod.DeepCopy()
		kubeSchedulerPod.Name = "kube-scheduler"
		kubeSchedulerPod.Labels["role"] = "scheduler"

		plainClusterPod = plainPod.DeepCopy()
		plainClusterPod.Namespace = "kube-system"
		plainClusterPod.Labels["resources.gardener.cloud/managed-by"] = "gardener"
		plainClusterPod.Labels["gardener.cloud/role"] = "system-component"

		kubeProxyPod = plainClusterPod.DeepCopy()
		kubeProxyPod.Name = "kube-proxy"
		kubeProxyPod.Labels["role"] = "proxy"

		controlPlaneDikiPod = plainControlPlanePod.DeepCopy()
		controlPlaneDikiPod.Name = fmt.Sprintf("diki-%s-%s", v1r11.IDPodFiles, "aaaaaaaaaa")
		controlPlaneDikiPod.Namespace = "kube-system"
		controlPlaneDikiPod.Labels = map[string]string{}

		clusterPod = plainClusterPod.DeepCopy()
		clusterPod.Name = "1-shoot-pod"

		clusterDikiPod = plainClusterPod.DeepCopy()
		clusterDikiPod.Name = fmt.Sprintf("diki-%s-%s", v1r11.IDPodFiles, "bbbbbbbbbb")
		clusterDikiPod.Labels = map[string]string{}
	})

	DescribeTable("Run cases",
		func(etcdMainPodLabelInstance string, controlPlaneExecuteReturnString, clusterExecuteReturnString [][]string, controlPlaneExecuteReturnError, clusterExecuteReturnError [][]error, options *option.FileOwnerOptions, expectedCheckResults []rule.CheckResult) {
			clusterExecuteReturnString[0] = append(clusterExecuteReturnString[0], emptyMounts)
			clusterExecuteReturnError[0] = append(clusterExecuteReturnError[0], nil)
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(clusterExecuteReturnString, clusterExecuteReturnError)
			additionalReturnStrings := []string{emptyMounts, emptyMounts, emptyMounts, emptyMounts}
			additionalReturnErrors := []error{nil, nil, nil, nil}
			controlPlaneExecuteReturnString[0] = append(controlPlaneExecuteReturnString[0], additionalReturnStrings...)
			controlPlaneExecuteReturnError[0] = append(controlPlaneExecuteReturnError[0], additionalReturnErrors...)
			fakeControlPlanePodContext = fakepod.NewFakeSimplePodContext(controlPlaneExecuteReturnString, controlPlaneExecuteReturnError)
			r := &v1r11.RulePodFiles{
				Logger:                 testLogger,
				InstanceID:             instanceID,
				ClusterClient:          fakeClusterClient,
				ControlPlaneClient:     fakeControlPlaneClient,
				ControlPlaneNamespace:  controlPlaneNamespace,
				ClusterPodContext:      fakeClusterPodContext,
				ControlPlanePodContext: fakeControlPlanePodContext,
				Options:                options,
			}

			Expect(fakeClusterClient.Create(ctx, clusterNode)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, controlPlaneNode)).To(Succeed())
			if len(etcdMainPodLabelInstance) > 0 {
				etcdMainPod.Labels["instance"] = etcdMainPodLabelInstance
			}
			Expect(fakeControlPlaneClient.Create(ctx, kubeControllerManagerPod)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, etcdMainPod)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, etcdEventsPod)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, kubeAPIPod)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, kubeSchedulerPod)).To(Succeed())
			Expect(fakeClusterClient.Create(ctx, kubeProxyPod)).To(Succeed())
			Expect(fakeClusterClient.Create(ctx, clusterPod)).To(Succeed())

			Expect(fakeControlPlaneClient.Create(ctx, controlPlaneDikiPod)).To(Succeed())
			Expect(fakeClusterClient.Create(ctx, clusterDikiPod)).To(Succeed())

			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},
		Entry("should return correct checkResults when options are used", "",
			[][]string{{mounts, compliantStats}}, [][]string{{mounts, compliantStats}},
			[][]error{{nil, nil}}, [][]error{{nil, nil}},
			&option.FileOwnerOptions{
				ExpectedFileOwner: option.ExpectedOwner{
					Users:  []string{"0", "65532"},
					Groups: []string{"0", "65532"},
				},
			},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions and expected owner", rule.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/file1.txt, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", rule.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/bar/file2.txt, permissions: 644, ownerUser: 0, ownerGroup: 65532")),
				rule.PassedCheckResult("File has expected permissions and expected owner", rule.NewTarget("cluster", "shoot", "name", "1-shoot-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /destination/file1.txt, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", rule.NewTarget("cluster", "shoot", "name", "1-shoot-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /destination/bar/file2.txt, permissions: 644, ownerUser: 0, ownerGroup: 65532")),
			}),
		Entry("should return correct checkResults when options are nil", "",
			[][]string{{mounts, compliantStats}}, [][]string{{mounts, compliantStats}},
			[][]error{{nil, nil}}, [][]error{{nil, nil}}, nil,
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions and expected owner", rule.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/file1.txt, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/bar/file2.txt, ownerGroup: 65532, expectedOwnerGroups: [0]")),
				rule.PassedCheckResult("File has expected permissions and expected owner", rule.NewTarget("cluster", "shoot", "name", "1-shoot-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /destination/file1.txt, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", rule.NewTarget("cluster", "shoot", "name", "1-shoot-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /destination/bar/file2.txt, permissions: 644, ownerUser: 0, ownerGroup: 65532")),
			}),
		Entry("should return correct checkResult when container is etcd", "",
			[][]string{{mountsWithETCD, compliantStats}}, [][]string{{emptyMounts}},
			[][]error{{nil, nil}}, [][]error{{nil}}, &option.FileOwnerOptions{},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions and expected owner", rule.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/file1.txt, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/bar/file2.txt, permissions: 644, expectedPermissionsMax: 600")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/bar/file2.txt, ownerGroup: 65532, expectedOwnerGroups: [0]")),
			}),
		Entry("should return errored checkResults when podExecutor errors", "",
			[][]string{{mounts}}, [][]string{{mounts, compliantStats}},
			[][]error{{errors.New("foo")}}, [][]error{{nil, errors.New("bar")}}, &option.FileOwnerOptions{},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("cluster", "seed", "name", "diki-pod-files-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("cluster", "shoot", "name", "diki-pod-files-bbbbbbbbbb", "namespace", "kube-system", "kind", "pod")),
			}),
		Entry("should return failed checkResult when mandatory component not present", "not-etcd-main",
			[][]string{{emptyMounts}}, [][]string{{emptyMounts}},
			[][]error{{nil}}, [][]error{{nil}}, nil,
			[]rule.CheckResult{
				rule.FailedCheckResult("Mandatory Component not found!", rule.NewTarget("cluster", "seed", "details", "missing ETCD Main")),
			}),
		Entry("should return all checkResult when mandatory component not present", "not-etcd-main",
			[][]string{{mountsWithETCD, compliantStats}}, [][]string{{emptyMounts}},
			[][]error{{nil, nil}}, [][]error{{nil}}, nil,
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions and expected owner", rule.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/file1.txt, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/bar/file2.txt, permissions: 644, expectedPermissionsMax: 600")),
				rule.FailedCheckResult("Mandatory Component not found!", rule.NewTarget("cluster", "seed", "details", "missing ETCD Main")),
			}),
		Entry("should return correct checkResult when checked files are *.key", "",
			[][]string{{mounts, keyFileStats}}, [][]string{{emptyMounts}},
			[][]error{{nil, nil}}, [][]error{{nil}}, nil,
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions and expected owner", rule.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/file1.key, permissions: 640, ownerUser: 0, ownerGroup: 0")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/bar/file2.key, permissions: 644, expectedPermissionsMax: 640")),
			}),
	)
})
