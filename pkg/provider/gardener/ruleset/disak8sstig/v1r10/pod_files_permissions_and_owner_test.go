// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10_test

import (
	"context"
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r10"
	"github.com/gardener/diki/pkg/rule"
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
	)

	var (
		instanceID                 = "1"
		fakeClusterClient          client.Client
		fakeControlPlaneClient     client.Client
		controlPlaneNamespace      = "foo"
		fakeClusterPodContext      pod.PodContext
		fakeControlPlanePodContext pod.PodContext
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
		v1r10.Generator = &FakeRandString{CurrentChar: 'a'}
		fakeClusterClient = fakeclient.NewClientBuilder().Build()
		fakeControlPlaneClient = fakeclient.NewClientBuilder().Build()
		plainPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{},
			},
			Spec: corev1.PodSpec{
				NodeName: "node01",
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
		controlPlaneDikiPod.Name = fmt.Sprintf("diki-%s-%s", v1r10.IDPodFiles, "aaaaaaaaaa")
		controlPlaneDikiPod.Namespace = "kube-system"
		controlPlaneDikiPod.Labels = map[string]string{}

		clusterPod = plainClusterPod.DeepCopy()
		clusterPod.Name = "1-shoot-pod"

		clusterDikiPod = plainClusterPod.DeepCopy()
		clusterDikiPod.Name = fmt.Sprintf("diki-%s-%s", v1r10.IDPodFiles, "bbbbbbbbbb")
		clusterDikiPod.Labels = map[string]string{}
	})

	DescribeTable("Run cases",
		func(etcdMainPodLabelInstance string, controlPlaneExecuteReturnString, clusterExecuteReturnString [][]string, controlPlaneExecuteReturnError, clusterExecuteReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			clusterExecuteReturnString[0] = append(clusterExecuteReturnString[0], emptyMounts)
			clusterExecuteReturnError[0] = append(clusterExecuteReturnError[0], nil)
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(clusterExecuteReturnString, clusterExecuteReturnError)
			additionalReturnStrings := []string{emptyMounts, emptyMounts, emptyMounts, emptyMounts}
			additionalReturnErrors := []error{nil, nil, nil, nil}
			controlPlaneExecuteReturnString[0] = append(controlPlaneExecuteReturnString[0], additionalReturnStrings...)
			controlPlaneExecuteReturnError[0] = append(controlPlaneExecuteReturnError[0], additionalReturnErrors...)
			fakeControlPlanePodContext = fakepod.NewFakeSimplePodContext(controlPlaneExecuteReturnString, controlPlaneExecuteReturnError)
			r := &v1r10.RulePodFiles{
				Logger:                 testLogger,
				InstanceID:             instanceID,
				ClusterClient:          fakeClusterClient,
				ControlPlaneClient:     fakeControlPlaneClient,
				ControlPlaneNamespace:  controlPlaneNamespace,
				ClusterPodContext:      fakeClusterPodContext,
				ControlPlanePodContext: fakeControlPlanePodContext,
			}

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

		Entry("should return passed checkResults when all files comply", "",
			[][]string{{mounts, compliantStats}}, [][]string{{mounts, compliantStats}},
			[][]error{{nil, nil}}, [][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/file1.txt, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/bar/file2.txt, permissions: 644, ownerUser: 0, ownerGroup: 65532")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "name", "1-shoot-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /destination/file1.txt, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "name", "1-shoot-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /destination/bar/file2.txt, permissions: 644, ownerUser: 0, ownerGroup: 65532")),
			}),
		Entry("should return correct checkResult when container is etcd", "",
			[][]string{{mountsWithETCD, compliantStats}}, [][]string{{emptyMounts}},
			[][]error{{nil, nil}}, [][]error{{nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/file1.txt, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.FailedCheckResult("File has too wide permissions", gardener.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /destination/bar/file2.txt, permissions: 644, expectedPermissionsMax: 600")),
			}),
		Entry("should return errored checkResults when podExecutor errors", "",
			[][]string{{mounts}}, [][]string{{mounts, compliantStats}},
			[][]error{{errors.New("foo")}}, [][]error{{nil, errors.New("bar")}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", gardener.NewTarget("cluster", "seed", "name", "diki-pod-files-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("bar", gardener.NewTarget("cluster", "shoot", "name", "diki-pod-files-bbbbbbbbbb", "namespace", "kube-system", "kind", "pod")),
			}),
		Entry("should return failed checkResults when mandatory component not present", "not-etcd-main",
			[][]string{{mounts}}, [][]string{{mounts, compliantStats}},
			[][]error{{errors.New("foo")}}, [][]error{{nil, errors.New("bar")}},
			[]rule.CheckResult{
				rule.FailedCheckResult("Mandatory Component not found!", gardener.NewTarget("cluster", "seed", "details", "missing ETCD Main")),
			}),
	)
})
