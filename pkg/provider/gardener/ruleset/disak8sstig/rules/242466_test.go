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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	fakestrgen "github.com/gardener/diki/pkg/internal/stringgen/fake"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#242466", func() {
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
		tlsKubeletConfig = `
tlsPrivateKeyFile: /var/lib/keys/tls.key
tlsCertFile: /var/lib/certs/tls.crt`
		kubeletPID         = "1"
		kubeletCommand     = "--config=var/lib/kubelet/config"
		kubeletCommandCert = "--config=var/lib/kubelet/config --cert-dir"
		emptyMounts        = `[]`
		compliantStats     = "644\t0\t0\tregular file\t/destination/file1.crt\n400\t0\t65532\tregular file\t/destination/bar/file2.pem"
		compliantCertStats = "644\t0\t0\tregular file\t/var/lib/certs/tls.crt\n"
		compliantStats2    = "600\t0\t0\tregular file\t/destination/file3.crt\n600\t1000\t0\tregular file\t/destination/bar/file4.txt\n"
		noCrtStats         = "600\t0\t0\tregular file\t/destination/file3.txt\n600\t1000\t0\tregular file\t/destination/bar/file4.txt\n"
		nonCompliantStats  = "664\t0\t0\tregular file\t/destination/file1.crt\n700\t0\t0\tregular file\t/destination/bar/file2.pem\n"
	)
	var (
		instanceID                 = "1"
		fakeControlPlaneClient     client.Client
		fakeClusterClient          client.Client
		Namespace                  = "foo"
		fakeControlPlanePodContext pod.PodContext
		fakeClusterPodContext      pod.PodContext
		nodeName                   = "node01"
		controlPlaneNode           *corev1.Node
		clusterNode                *corev1.Node
		plainDeployment            *appsv1.Deployment
		plainReplicaSet            *appsv1.ReplicaSet
		plainPod                   *corev1.Pod
		etcdMainPod                *corev1.Pod
		etcdEventsPod              *corev1.Pod
		kubeAPIServerPod           *corev1.Pod
		kubeControllerManagerPod   *corev1.Pod
		kubeSchedulerPod           *corev1.Pod
		kubeProxyPod               *corev1.Pod
		fooPod                     *corev1.Pod
		controlPlaneDikiPod        *corev1.Pod
		clusterDikiPod             *corev1.Pod
		ctx                        = context.TODO()
	)

	BeforeEach(func() {
		sharedrules.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
		fakeControlPlaneClient = fakeclient.NewClientBuilder().Build()
		fakeClusterClient = fakeclient.NewClientBuilder().Build()

		controlPlaneNode = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{
					"pods": resource.MustParse("100.0"),
				},
			},
		}

		clusterNode = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
				Labels: map[string]string{
					"worker.gardener.cloud/pool": "1",
				},
			},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{
					"pods": resource.MustParse("100.0"),
				},
			},
		}

		plainDeployment = &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "foo",
			},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name: "test",
							},
						},
					},
				},
			},
		}

		kubeAPIServerDep := plainDeployment.DeepCopy()
		kubeAPIServerDep.Name = "kube-apiserver"
		kubeAPIServerDep.UID = "11"

		kubeControllerManagerDep := plainDeployment.DeepCopy()
		kubeControllerManagerDep.Name = "kube-controller-manager"
		kubeControllerManagerDep.UID = "21"

		kubeSchedulerDep := plainDeployment.DeepCopy()
		kubeSchedulerDep.Name = "kube-scheduler"
		kubeSchedulerDep.UID = "31"

		plainReplicaSet = &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "foo",
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind: "Deployment",
					},
				},
			},
			Spec: appsv1.ReplicaSetSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name: "test",
							},
						},
					},
				},
			},
		}

		kubeAPIServerRS := plainReplicaSet.DeepCopy()
		kubeAPIServerRS.Name = "kube-apiserver"
		kubeAPIServerRS.UID = "12"
		kubeAPIServerRS.OwnerReferences[0].UID = "11"

		kubeControllerManagerRS := plainReplicaSet.DeepCopy()
		kubeControllerManagerRS.Name = "kube-controller-manager"
		kubeControllerManagerRS.UID = "22"
		kubeControllerManagerRS.OwnerReferences[0].UID = "21"

		kubeSchedulerRS := plainReplicaSet.DeepCopy()
		kubeSchedulerRS.Name = "kube-scheduler"
		kubeSchedulerRS.UID = "32"
		kubeSchedulerRS.OwnerReferences[0].UID = "31"

		plainPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Labels:    map[string]string{},
				Namespace: "foo",
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind: "ReplicaSet",
					},
				},
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
		etcdMainPod.OwnerReferences[0].UID = "1"

		etcdEventsPod = plainPod.DeepCopy()
		etcdEventsPod.Name = "etcd-events"
		etcdEventsPod.Labels["name"] = "etcd"
		etcdEventsPod.Labels["app.kubernetes.io/part-of"] = "etcd-events"
		etcdEventsPod.OwnerReferences[0].UID = "2"

		kubeAPIServerPod = plainPod.DeepCopy()
		kubeAPIServerPod.Name = "kube-apiserver"
		kubeAPIServerPod.Labels["name"] = "kube-apiserver"
		kubeAPIServerPod.OwnerReferences[0].UID = "12"

		kubeControllerManagerPod = plainPod.DeepCopy()
		kubeControllerManagerPod.Name = "kube-controller-manager"
		kubeControllerManagerPod.Labels["name"] = "kube-controller-manager"
		kubeControllerManagerPod.OwnerReferences[0].UID = "22"

		kubeSchedulerPod = plainPod.DeepCopy()
		kubeSchedulerPod.Name = "kube-scheduler"
		kubeSchedulerPod.Labels["name"] = "kube-scheduler"
		kubeSchedulerPod.OwnerReferences[0].UID = "32"

		kubeProxyPod = plainPod.DeepCopy()
		kubeProxyPod.Name = "1-pod"
		kubeProxyPod.Labels["role"] = "proxy"
		kubeProxyPod.OwnerReferences[0].UID = "1"

		fooPod = plainPod.DeepCopy()
		fooPod.Name = "foo"

		controlPlaneDikiPod = plainPod.DeepCopy()
		controlPlaneDikiPod.Name = fmt.Sprintf("diki-%s-%s", sharedrules.ID242466, "aaaaaaaaaa")
		controlPlaneDikiPod.Namespace = "kube-system"
		controlPlaneDikiPod.Labels = map[string]string{}

		clusterDikiPod = plainPod.DeepCopy()
		clusterDikiPod.Name = fmt.Sprintf("diki-%s-%s", sharedrules.ID242466, "cccccccccc")
		clusterDikiPod.Namespace = "kube-system"
		clusterDikiPod.Labels = map[string]string{}

		Expect(fakeControlPlaneClient.Create(ctx, controlPlaneNode)).To(Succeed())
		Expect(fakeControlPlaneClient.Create(ctx, fooPod)).To(Succeed())
		Expect(fakeControlPlaneClient.Create(ctx, kubeAPIServerDep)).To(Succeed())
		Expect(fakeControlPlaneClient.Create(ctx, kubeControllerManagerDep)).To(Succeed())
		Expect(fakeControlPlaneClient.Create(ctx, kubeSchedulerDep)).To(Succeed())
		Expect(fakeControlPlaneClient.Create(ctx, kubeAPIServerRS)).To(Succeed())
		Expect(fakeControlPlaneClient.Create(ctx, kubeControllerManagerRS)).To(Succeed())
		Expect(fakeControlPlaneClient.Create(ctx, kubeSchedulerRS)).To(Succeed())
	})

	It("should error when pods cannot be found", func() {
		mainSelector := labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": "etcd-main"})
		eventsSelector := labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": "etcd-events"})
		kubeProxySelector := labels.SelectorFromSet(labels.Set{"role": "proxy"})
		fakeControlPlanePodContext = fakepod.NewFakeSimplePodContext([][]string{}, [][]error{})
		fakeClusterPodContext = fakepod.NewFakeSimplePodContext([][]string{}, [][]error{})
		r := &rules.Rule242466{
			Logger:                 testLogger,
			InstanceID:             instanceID,
			ControlPlaneClient:     fakeControlPlaneClient,
			ClusterClient:          fakeClusterClient,
			ControlPlaneNamespace:  Namespace,
			ControlPlanePodContext: fakeControlPlanePodContext,
			ClusterPodContext:      fakeClusterPodContext,
		}

		ruleResult, err := r.Run(ctx)
		target := rule.NewTarget("cluster", "seed", "namespace", r.ControlPlaneNamespace)
		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf([]rule.CheckResult{
			rule.ErroredCheckResult("pods not found", target.With("selector", mainSelector.String())),
			rule.ErroredCheckResult("pods not found", target.With("selector", eventsSelector.String())),
			rule.ErroredCheckResult("pods not found for deployment", target.With("name", "kube-apiserver", "kind", "Deployment")),
			rule.ErroredCheckResult("pods not found for deployment", target.With("name", "kube-controller-manager", "kind", "Deployment")),
			rule.ErroredCheckResult("pods not found for deployment", target.With("name", "kube-scheduler", "kind", "Deployment")),
			rule.ErroredCheckResult("no allocatable nodes could be selected", rule.NewTarget("cluster", "shoot")),
			rule.ErroredCheckResult("pods not found", rule.NewTarget("cluster", "shoot", "selector", kubeProxySelector.String())),
		}))
	})

	//TODO: Remove these describe table test cases once support for the instance labels is deprecated
	DescribeTable("Run temporary instance label cases",
		func(includeETCDEventsPod bool, seedExecuteReturnString, shootExecuteReturnString [][]string, seedExecuteReturnError, shootExecuteReturnError [][]error, option *option.KubeProxyOptions, expectedCheckResults []rule.CheckResult) {
			oldSelectorETCDMainPod := etcdMainPod.DeepCopy()
			delete(oldSelectorETCDMainPod.Labels, "app.kubernetes.io/part-of")
			oldSelectorETCDMainPod.Labels["instance"] = "etcd-main"
			Expect(fakeControlPlaneClient.Create(ctx, oldSelectorETCDMainPod))

			if includeETCDEventsPod {
				oldSelectorETCDEventsPod := etcdEventsPod.DeepCopy()
				delete(oldSelectorETCDEventsPod.Labels, "app.kubernetes.io/part-of")
				oldSelectorETCDEventsPod.Labels["instance"] = "etcd-events"
				Expect(fakeControlPlaneClient.Create(ctx, oldSelectorETCDEventsPod))
			}

			Expect(fakeControlPlaneClient.Create(ctx, kubeAPIServerPod)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, kubeControllerManagerPod)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, kubeSchedulerPod)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, controlPlaneDikiPod)).To(Succeed())

			Expect(fakeClusterClient.Create(ctx, clusterNode)).To(Succeed())
			Expect(fakeClusterClient.Create(ctx, kubeProxyPod)).To(Succeed())
			Expect(fakeClusterClient.Create(ctx, clusterDikiPod)).To(Succeed())

			fakeControlPlanePodContext = fakepod.NewFakeSimplePodContext(seedExecuteReturnString, seedExecuteReturnError)
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(shootExecuteReturnString, shootExecuteReturnError)
			r := &rules.Rule242466{
				Logger:                 testLogger,
				InstanceID:             instanceID,
				ControlPlaneClient:     fakeControlPlaneClient,
				ClusterClient:          fakeClusterClient,
				ControlPlaneNamespace:  Namespace,
				ControlPlanePodContext: fakeControlPlanePodContext,
				ClusterPodContext:      fakeClusterPodContext,
				Options:                option,
			}

			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
		},
		Entry("should return correct errored checkResults when old ETCD pods are partially found", false,
			[][]string{{mounts, compliantStats, emptyMounts, emptyMounts, emptyMounts}},
			[][]string{{kubeletPID, kubeletCommand, tlsKubeletConfig, compliantCertStats}, {mounts, compliantStats}},
			[][]error{{nil, nil, nil, nil, nil}},
			[][]error{{nil, nil, nil, nil}, {nil, nil}}, nil,
			[]rule.CheckResult{
				rule.ErroredCheckResult("pods not found", rule.NewTarget("cluster", "seed", "namespace", "foo", "selector", "instance=etcd-events")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "seed", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "seed", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "shoot", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "shoot", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "shoot", "name", "node01", "kind", "node", "details", "fileName: /var/lib/certs/tls.crt, permissions: 644")),
			}),
		Entry("should return passed checkResults from ETCD pods with old labels", true,
			[][]string{{mounts, compliantStats, mounts, compliantStats2, emptyMounts, emptyMounts, emptyMounts}},
			[][]string{{kubeletPID, kubeletCommand, tlsKubeletConfig, compliantCertStats}, {mounts, compliantStats}},
			[][]error{{nil, nil, nil, nil, nil, nil, nil}},
			[][]error{{nil, nil, nil, nil}, {nil, nil}}, nil,
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "seed", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "seed", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "seed", "name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file3.crt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "shoot", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "shoot", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "shoot", "name", "node01", "kind", "node", "details", "fileName: /var/lib/certs/tls.crt, permissions: 644")),
			}))

	DescribeTable("Run cases",
		func(seedExecuteReturnString, shootExecuteReturnString [][]string, seedExecuteReturnError, shootExecuteReturnError [][]error, option *option.KubeProxyOptions, expectedCheckResults []rule.CheckResult) {
			Expect(fakeControlPlaneClient.Create(ctx, etcdMainPod)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, etcdEventsPod)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, kubeAPIServerPod)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, kubeControllerManagerPod)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, kubeSchedulerPod)).To(Succeed())
			Expect(fakeControlPlaneClient.Create(ctx, controlPlaneDikiPod)).To(Succeed())

			Expect(fakeClusterClient.Create(ctx, clusterNode)).To(Succeed())
			Expect(fakeClusterClient.Create(ctx, kubeProxyPod)).To(Succeed())
			Expect(fakeClusterClient.Create(ctx, clusterDikiPod)).To(Succeed())

			fakeControlPlanePodContext = fakepod.NewFakeSimplePodContext(seedExecuteReturnString, seedExecuteReturnError)
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(shootExecuteReturnString, shootExecuteReturnError)
			r := &rules.Rule242466{
				Logger:                 testLogger,
				InstanceID:             instanceID,
				ControlPlaneClient:     fakeControlPlaneClient,
				ClusterClient:          fakeClusterClient,
				ControlPlaneNamespace:  Namespace,
				ControlPlanePodContext: fakeControlPlanePodContext,
				ClusterPodContext:      fakeClusterPodContext,
				Options:                option,
			}

			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
		},
		Entry("should return passed checkResults when files have expected permissions",
			[][]string{{mounts, compliantStats, mounts, compliantStats2, emptyMounts, emptyMounts, emptyMounts}},
			[][]string{{kubeletPID, kubeletCommand, tlsKubeletConfig, compliantCertStats}, {mounts, compliantStats}},
			[][]error{{nil, nil, nil, nil, nil, nil, nil}},
			[][]error{{nil, nil, nil, nil}, {nil, nil}}, nil,
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "seed", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "seed", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "seed", "name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file3.crt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "shoot", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "shoot", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "shoot", "name", "node01", "kind", "node", "details", "fileName: /var/lib/certs/tls.crt, permissions: 644")),
			}),
		Entry("should return failed checkResults when files have too wide permissions",
			[][]string{{mounts, nonCompliantStats, emptyMounts, emptyMounts, emptyMounts, emptyMounts}},
			[][]string{{kubeletPID, kubeletCommand, "", nonCompliantStats}, {mounts, nonCompliantStats}},
			[][]error{{nil, nil, nil, nil, nil, nil}},
			[][]error{{nil, nil, nil, nil}, {nil, nil}}, nil,
			[]rule.CheckResult{
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "seed", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 664, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "seed", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 700, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "shoot", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 664, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "shoot", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 700, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "shoot", "name", "node01", "kind", "node", "details", "fileName: /destination/file1.crt, permissions: 664, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "shoot", "name", "node01", "kind", "node", "details", "fileName: /destination/bar/file2.pem, permissions: 700, expectedPermissionsMax: 644")),
			}),
		Entry("should return failed checkResults when crt files cannot be found in PKI dir",
			[][]string{{emptyMounts, emptyMounts, emptyMounts, emptyMounts, emptyMounts}},
			[][]string{{kubeletPID, kubeletCommand, "", noCrtStats}, {emptyMounts}},
			[][]error{{nil, nil, nil, nil, nil}},
			[][]error{{nil, nil, nil, nil}, {nil, nil}}, nil,
			[]rule.CheckResult{
				rule.ErroredCheckResult("no '.crt' files found in PKI directory", rule.NewTarget("cluster", "shoot", "name", "node01", "kind", "node", "directory", "/var/lib/kubelet/pki")),
			}),
		Entry("should return accepted check result when kubeProxyDiabled option is set to true",
			[][]string{{mounts, nonCompliantStats, emptyMounts, emptyMounts, emptyMounts, emptyMounts}},
			[][]string{{kubeletPID, kubeletCommand, "", nonCompliantStats}},
			[][]error{{nil, nil, nil, nil, nil, nil}},
			[][]error{{nil, nil, nil, nil}},
			&option.KubeProxyOptions{
				KubeProxyDisabled: true,
			},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "seed", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 664, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "seed", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 700, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "shoot", "name", "node01", "kind", "node", "details", "fileName: /destination/file1.crt, permissions: 664, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "shoot", "name", "node01", "kind", "node", "details", "fileName: /destination/bar/file2.pem, permissions: 700, expectedPermissionsMax: 644")),
				rule.AcceptedCheckResult("kube-proxy check is skipped.", rule.NewTarget("cluster", "shoot")),
			}),
		Entry("should correctly return errored checkResults when commands error",
			[][]string{{mounts, mounts, compliantStats2, emptyMounts, emptyMounts, emptyMounts}},
			[][]string{{kubeletPID}, {emptyMounts}},
			[][]error{{errors.New("foo"), nil, errors.New("bar"), nil, nil, nil}},
			[][]error{{errors.New("foo-bar")}, {nil}}, nil,
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("cluster", "seed", "name", "diki-242466-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("cluster", "seed", "name", "diki-242466-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("foo-bar", rule.NewTarget("cluster", "shoot", "name", "diki-242466-bbbbbbbbbb", "namespace", "kube-system", "kind", "pod")),
			}),
		Entry("should check files when GetMountedFilesStats errors",
			[][]string{{mountsMulty, compliantStats, emptyMounts, emptyMounts, emptyMounts, emptyMounts, emptyMounts}},
			[][]string{{kubeletPID, kubeletCommandCert, "", compliantCertStats}, {emptyMounts}},
			[][]error{{nil, nil, errors.New("bar"), nil, nil, nil, nil}},
			[][]error{{nil, nil, nil, nil}, {nil, nil}}, nil,
			[]rule.CheckResult{
				rule.ErroredCheckResult("bar", rule.NewTarget("cluster", "seed", "name", "diki-242466-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "seed", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "seed", "name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
				rule.ErroredCheckResult("kubelet cert-dir flag set to empty", rule.NewTarget("cluster", "shoot", "name", "diki-242466-bbbbbbbbbb", "namespace", "kube-system", "kind", "pod")),
			}),
		Entry("should correctly return all checkResults when commands error",
			[][]string{{mounts, mounts, compliantStats2, emptyMounts, emptyMounts, emptyMounts}},
			[][]string{{kubeletPID, kubeletCommand, tlsKubeletConfig}, {emptyMounts}},
			[][]error{{errors.New("foo"), nil, nil, nil, nil, nil}},
			[][]error{{nil, nil, errors.New("bar")}, {nil, nil}}, nil,
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("cluster", "seed", "name", "diki-242466-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "seed", "name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file3.crt, permissions: 600")),
				rule.ErroredCheckResult("could not retrieve kubelet config: bar", rule.NewTarget("cluster", "shoot", "name", "diki-242466-bbbbbbbbbb", "namespace", "kube-system", "kind", "pod")),
			}),
	)
})
