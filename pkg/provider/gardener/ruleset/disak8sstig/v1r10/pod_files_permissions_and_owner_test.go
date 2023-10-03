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
    "destination": "/destination",
    "source": "/foo"
  }
]`
		emptyMounts    = `[]`
		mountsWithETCD = `[
  {
    "destination": "/destination/etcd/data",
    "source": "/source"
  }
]`
		compliantStats = `600 0 0 /source/file1.txt
644 0 65534 /source/bar/file2.txt`
	)

	var (
		instanceID                 = "1"
		fakeClusterClient          client.Client
		fakeControlPlaneClient     client.Client
		controlPlaneNamespace      = "foo"
		fakeClusterPodContext      pod.PodContext
		fakeControlPlanePodContext pod.PodContext
		controlPlanePod            *corev1.Pod
		etcdEventsPod              *corev1.Pod
		kubeAPIPod                 *corev1.Pod
		kubeSchedulerPod           *corev1.Pod
		kubeControllerManagerPod   *corev1.Pod
		kubeProxyPod               *corev1.Pod
		controlPlaneDikiPod        *corev1.Pod
		clusterPod                 *corev1.Pod
		clusterDikiPod             *corev1.Pod
		ctx                        = context.TODO()
	)

	BeforeEach(func() {
		v1r10.Generator = &FakeRandString{CurrentChar: 'a'}
		fakeClusterClient = fakeclient.NewClientBuilder().Build()
		fakeControlPlaneClient = fakeclient.NewClientBuilder().Build()
		controlPlanePod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "1-seed-pod",
				Namespace: controlPlaneNamespace,
				Labels: map[string]string{
					"name":                "etcd",
					"instance":            "etcd-main",
					"gardener.cloud/role": "controlplane",
				},
			},
			Spec: corev1.PodSpec{
				NodeName: "node01",
				Containers: []corev1.Container{
					{
						Name: "test",
						VolumeMounts: []corev1.VolumeMount{
							{
								MountPath: "/source",
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
		etcdEventsPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "etcd-events",
				Namespace: controlPlaneNamespace,
				Labels: map[string]string{
					"name":                "etcd",
					"instance":            "etcd-events",
					"gardener.cloud/role": "controlplane",
				},
			},
			Spec: corev1.PodSpec{
				NodeName: "node01",
				Containers: []corev1.Container{
					{
						Name: "test",
						VolumeMounts: []corev1.VolumeMount{
							{
								MountPath: "/source",
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
		kubeAPIPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-api",
				Namespace: controlPlaneNamespace,
				Labels: map[string]string{
					"role":                "apiserver",
					"gardener.cloud/role": "controlplane",
				},
			},
			Spec: corev1.PodSpec{
				NodeName: "node01",
				Containers: []corev1.Container{
					{
						Name: "test",
						VolumeMounts: []corev1.VolumeMount{
							{
								MountPath: "/source",
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
		kubeControllerManagerPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-controller-manager",
				Namespace: controlPlaneNamespace,
				Labels: map[string]string{
					"role":                "controller-manager",
					"gardener.cloud/role": "controlplane",
				},
			},
			Spec: corev1.PodSpec{
				NodeName: "node01",
				Containers: []corev1.Container{
					{
						Name: "test",
						VolumeMounts: []corev1.VolumeMount{
							{
								MountPath: "/source",
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
		kubeSchedulerPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-scheduler",
				Namespace: controlPlaneNamespace,
				Labels: map[string]string{
					"role":                "scheduler",
					"gardener.cloud/role": "controlplane",
				},
			},
			Spec: corev1.PodSpec{
				NodeName: "node01",
				Containers: []corev1.Container{
					{
						Name: "test",
						VolumeMounts: []corev1.VolumeMount{
							{
								MountPath: "/source",
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
		kubeProxyPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-proxy",
				Namespace: "kube-system",
				Labels: map[string]string{
					"role":                                "proxy",
					"resources.gardener.cloud/managed-by": "gardener",
					"gardener.cloud/role":                 "system-component",
				},
			},
			Spec: corev1.PodSpec{
				NodeName: "node01",
				Containers: []corev1.Container{
					{
						Name: "test",
						VolumeMounts: []corev1.VolumeMount{
							{
								MountPath: "/source",
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
		controlPlaneDikiPodName := fmt.Sprintf("diki-%s-%s", v1r10.IDPodFiles, "aaaaaaaaaa")
		controlPlaneDikiPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      controlPlaneDikiPodName,
				Namespace: "kube-system",
			},
			Spec: corev1.PodSpec{
				NodeName: "node01",
				Containers: []corev1.Container{
					{
						Name: "test",
						VolumeMounts: []corev1.VolumeMount{
							{
								MountPath: "/source",
							},
						},
					},
				},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						ContainerID: "containerd://foo",
					},
				},
			},
		}
		clusterPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "1-shoot-pod",
				Namespace: "kube-system",
				Labels: map[string]string{
					"resources.gardener.cloud/managed-by": "gardener",
					"gardener.cloud/role":                 "system-component",
				},
			},
			Spec: corev1.PodSpec{
				NodeName: "node01",
				Containers: []corev1.Container{
					{
						Name: "test",
						VolumeMounts: []corev1.VolumeMount{
							{
								MountPath: "/source",
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
		clusterDikiPodName := fmt.Sprintf("diki-%s-%s", v1r10.IDPodFiles, "bbbbbbbbbb")
		clusterDikiPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterDikiPodName,
				Namespace: "kube-system",
			},
			Spec: corev1.PodSpec{
				NodeName: "node01",
				Containers: []corev1.Container{
					{
						Name: "test",
						VolumeMounts: []corev1.VolumeMount{
							{
								MountPath: "/source",
							},
						},
					},
				},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						ContainerID: "containerd://foo",
					},
				},
			},
		}
	})

	DescribeTable("Run cases",
		func(controlPlanePodLabelInstance string, controlPlaneExecuteReturnString, clusterExecuteReturnString [][]string, controlPlaneExecuteReturnError, clusterExecuteReturnError [][]error, expectedCheckResults []rule.CheckResult) {
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

			if len(controlPlanePodLabelInstance) > 0 {
				controlPlanePod.Labels["instance"] = controlPlanePodLabelInstance
			}
			Expect(fakeControlPlaneClient.Create(ctx, kubeControllerManagerPod)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, controlPlanePod)).To(Succeed())
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
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /source/file1.txt, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /source/bar/file2.txt, permissions: 644, ownerUser: 0, ownerGroup: 65534")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "name", "1-shoot-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /source/file1.txt, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "shoot", "name", "1-shoot-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /source/bar/file2.txt, permissions: 644, ownerUser: 0, ownerGroup: 65534")),
			}),
		Entry("should return correct checkResult when container is etcd", "",
			[][]string{{mountsWithETCD, compliantStats}}, [][]string{{emptyMounts}},
			[][]error{{nil, nil}}, [][]error{{nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions and expected owner", gardener.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /source/file1.txt, permissions: 600, ownerUser: 0, ownerGroup: 0")),
				rule.FailedCheckResult("File has too wide permissions", gardener.NewTarget("cluster", "seed", "name", "1-seed-pod", "namespace", "foo", "kind", "pod", "details", "fileName: /source/bar/file2.txt, permissions: 644, expectedPermissionsMax: 600")),
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
