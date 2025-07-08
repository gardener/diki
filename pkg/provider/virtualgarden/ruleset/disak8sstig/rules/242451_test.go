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
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#242451", func() {
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
		emptyMounts           = `[]`
		compliantFileStats    = "600\t0\t0\tregular file\t/destination/file1.key\n400\t0\t0\tregular file\t/destination/file2.pem"
		compliantDirStats     = "600\t0\t0\tdirectory\t/destination\n"
		compliantFileStats2   = "600\t0\t0\tregular file\t/destination/file3.crt\n600\t1000\t0\tregular file\t/destination/file4.txt\n"
		nonCompliantFileStats = "644\t0\t1000\tregular file\t/destination/file1.key\n700\t2000\t0\tregular file\t/destination/file2.pem\n"
		nonCompliantDirStats  = "600\t65532\t0\tdirectory\t/destination\n"
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
		kubeAPIServerRS.OwnerReferences[0] =
			metav1.OwnerReference{
				UID:        "11",
				Kind:       "Deployment",
				APIVersion: "apps/v1",
				Name:       "virtual-garden-kube-apiserver",
			}

		kubeControllerManagerRS := plainReplicaSet.DeepCopy()
		kubeControllerManagerRS.Name = "virtual-garden-kube-controller-manager"
		kubeControllerManagerRS.UID = "22"
		kubeControllerManagerRS.OwnerReferences[0] =
			metav1.OwnerReference{
				UID:        "21",
				Kind:       "Deployment",
				APIVersion: "apps/v1",
				Name:       "virtual-garden-kube-controller-manager",
			}

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
		etcdMainPod.OwnerReferences[0] =
			metav1.OwnerReference{
				UID:        "1",
				Kind:       "DaemonSet",
				APIVersion: "apps/v1",
				Name:       "etcd-main",
			}

		etcdEventsPod = plainPod.DeepCopy()
		etcdEventsPod.Name = "etcd-events"
		etcdEventsPod.Labels["name"] = "etcd"
		etcdEventsPod.Labels["app.kubernetes.io/part-of"] = "virtual-garden-etcd-events"
		etcdEventsPod.OwnerReferences[0] =
			metav1.OwnerReference{
				UID:        "2",
				Kind:       "DaemonSet",
				APIVersion: "apps/v1",
				Name:       "etcd-events",
			}

		kubeAPIServerPod = plainPod.DeepCopy()
		kubeAPIServerPod.Name = "virtual-garden-kube-apiserver"
		kubeAPIServerPod.OwnerReferences[0] =
			metav1.OwnerReference{
				UID:        "12",
				Kind:       "Deployment",
				APIVersion: "apps/v1",
				Name:       "virtual-garden-kube-apiserver",
			}

		kubeControllerManagerPod = plainPod.DeepCopy()
		kubeControllerManagerPod.Name = "virtual-garden-kube-controller-manager"
		kubeControllerManagerPod.OwnerReferences[0] =
			metav1.OwnerReference{
				UID:        "22",
				Kind:       "Deployment",
				APIVersion: "apps/v1",
				Name:       "virtual-garden-kube-controller-manager",
			}

		fooPod = plainPod.DeepCopy()
		fooPod.Name = "foo"

		dikiPod = plainPod.DeepCopy()
		dikiPod.Name = fmt.Sprintf("diki-%s-%s", sharedrules.ID242451, "aaaaaaaaaa")
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
		r := &rules.Rule242451{
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
		func(options *option.FileOwnerOptions, includeETCDMainPod bool, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			if includeETCDMainPod {
				oldSelectorETCDMainPod := etcdMainPod.DeepCopy()
				delete(oldSelectorETCDMainPod.Labels, "app.kubernetes.io/part-of")
				oldSelectorETCDMainPod.Labels["instance"] = "virtual-garden-etcd-main"
				Expect(fakeClient.Create(ctx, oldSelectorETCDMainPod))
			}

			oldSelectorETCDEventsPod := etcdEventsPod.DeepCopy()
			delete(oldSelectorETCDEventsPod.Labels, "app.kubernetes.io/part-of")
			oldSelectorETCDEventsPod.Labels["instance"] = "virtual-garden-etcd-events"
			Expect(fakeClient.Create(ctx, oldSelectorETCDEventsPod))

			Expect(fakeClient.Create(ctx, kubeAPIServerPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeControllerManagerPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod)).To(Succeed())

			fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &rules.Rule242451{
				Logger:     testLogger,
				InstanceID: instanceID,
				Client:     fakeClient,
				Namespace:  Namespace,
				PodContext: fakePodContext,
				Options:    options,
			}

			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
		},
		Entry("should return passed checkResults from ETCD pods with old labels", nil, true,
			[][]string{{mounts, compliantFileStats, compliantDirStats, mounts, compliantFileStats2, compliantDirStats, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file1.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file2.pem, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file3.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination, ownerUser: 0, ownerGroup: 0")),
			}),
		Entry("should return correct errored checkResults when old ETCD pods are partially found", nil, false,
			[][]string{{mounts, compliantFileStats2, compliantDirStats, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("pods not found", rule.NewTarget("selector", "instance=virtual-garden-etcd-main", "namespace", "foo")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file3.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination, ownerUser: 0, ownerGroup: 0")),
			}))

	DescribeTable("Run cases",
		func(options *option.FileOwnerOptions, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			Expect(fakeClient.Create(ctx, etcdMainPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, etcdEventsPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeAPIServerPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeControllerManagerPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod)).To(Succeed())

			fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &rules.Rule242451{
				Logger:     testLogger,
				InstanceID: instanceID,
				Client:     fakeClient,
				Namespace:  Namespace,
				PodContext: fakePodContext,
				Options:    options,
			}

			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
		},
		Entry("should return passed checkResults when files have expected owners", nil,
			[][]string{{mounts, compliantFileStats, compliantDirStats, mounts, compliantFileStats2, compliantDirStats, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file1.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file2.pem, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file3.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination, ownerUser: 0, ownerGroup: 0")),
			}),
		Entry("should return failed checkResults when files do not have expected owners", nil,
			[][]string{{mounts, nonCompliantFileStats, nonCompliantDirStats, emptyMounts, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file1.key, ownerGroup: 1000, expectedOwnerGroups: [0]")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file2.pem, ownerUser: 2000, expectedOwnerUsers: [0]")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination, ownerUser: 65532, expectedOwnerUsers: [0]")),
			}),
		Entry("should return correct checkResults when options are used", &option.FileOwnerOptions{
			ExpectedFileOwner: option.ExpectedOwner{
				Users:  []string{"0", "2000"},
				Groups: []string{"0", "1000"},
			},
		},
			[][]string{{mounts, nonCompliantFileStats, nonCompliantDirStats, emptyMounts, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file1.key, ownerUser: 0, ownerGroup: 1000")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file2.pem, ownerUser: 2000, ownerGroup: 0")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination, ownerUser: 65532, expectedOwnerUsers: [0 2000]")),
			}),
		Entry("should correctly return errored checkResults when commands error", nil,
			[][]string{{mounts, mounts, compliantFileStats2, mounts, compliantFileStats, "", emptyMounts}},
			[][]error{{errors.New("foo"), nil, errors.New("bar"), nil, nil, errors.New("foo-bar"), nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242451-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242451-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "virtual-garden-kube-apiserver", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file1.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "virtual-garden-kube-apiserver", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file2.pem, ownerUser: 0, ownerGroup: 0")),
				rule.ErroredCheckResult("foo-bar", rule.NewTarget("name", "diki-242451-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
			}),
		Entry("should check files when GetMountedFilesStats errors", nil,
			[][]string{{mountsMulty, compliantFileStats, emptyMounts, compliantDirStats, emptyMounts, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, errors.New("bar"), nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242451-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file1.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file2.pem, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-main", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination, ownerUser: 0, ownerGroup: 0")),
			}),
		Entry("should correctly return all checkResults when commands error", nil,
			[][]string{{mounts, mounts, compliantFileStats2, compliantDirStats, emptyMounts, emptyMounts}},
			[][]error{{errors.New("foo"), nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242451-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination/file3.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "etcd-events", "namespace", "foo", "containerName", "test", "kind", "DaemonSet", "details", "fileName: /destination, ownerUser: 0, ownerGroup: 0")),
			}),
	)
})
