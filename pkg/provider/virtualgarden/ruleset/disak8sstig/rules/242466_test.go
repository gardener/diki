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
	"github.com/gardener/diki/pkg/provider/virtualgarden/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
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
		emptyMounts       = `[]`
		compliantStats    = "644\t0\t0\tregular file\t/destination/file1.crt\n400\t0\t65532\tregular file\t/destination/bar/file2.pem"
		compliantStats2   = "600\t0\t0\tregular file\t/destination/file3.crt\n600\t1000\t0\tregular file\t/destination/bar/file4.txt\n"
		nonCompliantStats = "664\t0\t0\tregular file\t/destination/file1.crt\n700\t0\t0\tregular file\t/destination/bar/file2.pem\n"
	)
	var (
		instanceID               = "1"
		fakeClient               client.Client
		Namespace                = "foo"
		fakePodContext           pod.PodContext
		nodeName                 = "node01"
		Node                     *corev1.Node
		plainDeployment          *appsv1.Deployment
		plainReplicaSet          *appsv1.ReplicaSet
		plainPod                 *corev1.Pod
		etcdMainPod              *corev1.Pod
		etcdEventsPod            *corev1.Pod
		kubeAPIServerPod         *corev1.Pod
		kubeControllerManagerPod *corev1.Pod
		fooPod                   *corev1.Pod
		dikiPod                  *corev1.Pod
		ctx                      = context.TODO()
	)

	BeforeEach(func() {
		sharedrules.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
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
		kubeAPIServerDep.Name = "virtual-garden-kube-apiserver"
		kubeAPIServerDep.UID = "11"

		kubeControllerManagerDep := plainDeployment.DeepCopy()
		kubeControllerManagerDep.Name = "virtual-garden-kube-controller-manager"
		kubeControllerManagerDep.UID = "21"

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
		kubeAPIServerRS.Name = "virtual-garden-kube-apiserver"
		kubeAPIServerRS.UID = "12"
		kubeAPIServerRS.OwnerReferences[0].UID = "11"

		kubeControllerManagerRS := plainReplicaSet.DeepCopy()
		kubeControllerManagerRS.Name = "virtual-garden-kube-controller-manager"
		kubeControllerManagerRS.UID = "22"
		kubeControllerManagerRS.OwnerReferences[0].UID = "21"

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
		etcdMainPod.Labels["app.kubernetes.io/part-of"] = "virtual-garden-etcd-main"
		etcdMainPod.OwnerReferences[0].UID = "1"

		etcdEventsPod = plainPod.DeepCopy()
		etcdEventsPod.Name = "etcd-events"
		etcdEventsPod.Labels["name"] = "etcd"
		etcdEventsPod.Labels["app.kubernetes.io/part-of"] = "virtual-garden-etcd-events"
		etcdEventsPod.OwnerReferences[0].UID = "2"

		kubeAPIServerPod = plainPod.DeepCopy()
		kubeAPIServerPod.Name = "virtual-garden-kube-apiserver"
		kubeAPIServerPod.OwnerReferences[0].UID = "12"

		kubeControllerManagerPod = plainPod.DeepCopy()
		kubeControllerManagerPod.Name = "virtual-garden-kube-controller-manager"
		kubeControllerManagerPod.OwnerReferences[0].UID = "22"

		fooPod = plainPod.DeepCopy()
		fooPod.Name = "foo"

		dikiPod = plainPod.DeepCopy()
		dikiPod.Name = fmt.Sprintf("diki-%s-%s", sharedrules.ID242466, "aaaaaaaaaa")
		dikiPod.Namespace = "kube-system"
		dikiPod.Labels = map[string]string{}

		Expect(fakeClient.Create(ctx, Node)).To(Succeed())
		Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubeAPIServerDep)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubeControllerManagerDep)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubeAPIServerRS)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubeControllerManagerRS)).To(Succeed())
	})

	It("should fail when pods cannot be found", func() {
		mainSelector := labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": "virtual-garden-etcd-main"})
		eventsSelector := labels.SelectorFromSet(labels.Set{"app.kubernetes.io/part-of": "virtual-garden-etcd-events"})
		fakePodContext = fakepod.NewFakeSimplePodContext([][]string{}, [][]error{})
		r := &rules.Rule242466{
			Logger:     testLogger,
			InstanceID: instanceID,
			Client:     fakeClient,
			Namespace:  Namespace,
			PodContext: fakePodContext,
		}

		ruleResult, err := r.Run(ctx)
		target := rule.NewTarget("namespace", r.Namespace)
		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf([]rule.CheckResult{
			rule.ErroredCheckResult("pods not found", target.With("selector", mainSelector.String())),
			rule.ErroredCheckResult("pods not found", target.With("selector", eventsSelector.String())),
			rule.ErroredCheckResult("pods not found for deployment", target.With("name", "virtual-garden-kube-apiserver", "kind", "Deployment", "namespace", r.Namespace)),
			rule.ErroredCheckResult("pods not found for deployment", target.With("name", "virtual-garden-kube-controller-manager", "kind", "Deployment", "namespace", r.Namespace)),
		}))
	})

	//TODO: Remove these describe table test cases once support for the instance labels is deprecated
	DescribeTable("Run temporary instance label cases",
		func(includeETCDEventsPod bool, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			oldSelectorETCDMainPod := etcdMainPod.DeepCopy()
			delete(oldSelectorETCDMainPod.Labels, "app.kubernetes.io/part-of")
			oldSelectorETCDMainPod.Labels["instance"] = "virtual-garden-etcd-main"
			Expect(fakeClient.Create(ctx, oldSelectorETCDMainPod))

			if includeETCDEventsPod {
				oldSelectorETCDEventsPod := etcdEventsPod.DeepCopy()
				delete(oldSelectorETCDEventsPod.Labels, "app.kubernetes.io/part-of")
				oldSelectorETCDEventsPod.Labels["instance"] = "virtual-garden-etcd-events"
				Expect(fakeClient.Create(ctx, oldSelectorETCDEventsPod))
			}

			Expect(fakeClient.Create(ctx, kubeAPIServerPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeControllerManagerPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod)).To(Succeed())

			fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &rules.Rule242466{
				Logger:     testLogger,
				InstanceID: instanceID,
				Client:     fakeClient,
				Namespace:  Namespace,
				PodContext: fakePodContext,
			}

			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},
		Entry("should return passed checkResults from ETCD pods with old labels", true,
			[][]string{{mounts, compliantStats, mounts, compliantStats2, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file3.crt, permissions: 600")),
			}),
		Entry("should return correct errored checkResults when old ETCD pods are partially found", false,
			[][]string{{mounts, compliantStats, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("pods not found", rule.NewTarget("selector", "instance=virtual-garden-etcd-events", "namespace", "foo")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
			}))

	DescribeTable("Run cases",
		func(executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			Expect(fakeClient.Create(ctx, etcdMainPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, etcdEventsPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeAPIServerPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeControllerManagerPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod)).To(Succeed())

			fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &rules.Rule242466{
				Logger:     testLogger,
				InstanceID: instanceID,
				Client:     fakeClient,
				Namespace:  Namespace,
				PodContext: fakePodContext,
			}

			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},
		Entry("should return passed checkResults when files have expected permissions",
			[][]string{{mounts, compliantStats, mounts, compliantStats2, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file3.crt, permissions: 600")),
			}),
		Entry("should return failed checkResults when files have too wide permissions",
			[][]string{{mounts, nonCompliantStats, emptyMounts, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 664, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 700, expectedPermissionsMax: 644")),
			}),
		Entry("should correctly return errored checkResults when commands error",
			[][]string{{mounts, mounts, compliantStats2, emptyMounts, emptyMounts}},
			[][]error{{errors.New("foo"), nil, errors.New("bar"), nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242466-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242466-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
			}),
		Entry("should check files when GetMountedFilesStats errors",
			[][]string{{mountsMulty, compliantStats, emptyMounts, emptyMounts, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, errors.New("bar"), nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242466-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
			}),
		Entry("should correctly return all checkResults when commands error",
			[][]string{{mounts, mounts, compliantStats2, emptyMounts, emptyMounts}},
			[][]error{{errors.New("foo"), nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242466-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file3.crt, permissions: 600")),
			}),
	)
})
