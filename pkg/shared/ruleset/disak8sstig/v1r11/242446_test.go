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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	fakestrgen "github.com/gardener/diki/pkg/internal/stringgen/fake"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ = Describe("#242446", func() {
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
		compliantStats    = "644\t0\t0\tregular file\t/destination/file1.crt\n400\t0\t0\tregular file\t/destination/bar/file2.key"
		compliantStats2   = "600\t0\t0\tregular file\t/destination/file3.key\n600\t0\t0\tregular file\t/destination/bar/file4.txt\n"
		nonCompliantStats = "664\t0\t1000\tregular file\t/destination/file1.key\n700\t2000\t0\tregular file\t/destination/bar/file2.key\n"
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
		kubeAPIServerPod         *corev1.Pod
		kubeControllerManagerPod *corev1.Pod
		kubeSchedulerPod         *corev1.Pod
		fooPod                   *corev1.Pod
		dikiPod                  *corev1.Pod
		ctx                      = context.TODO()
	)

	BeforeEach(func() {
		v1r11.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
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

		fooPod = plainPod.DeepCopy()
		fooPod.Name = "foo"

		dikiPod = plainPod.DeepCopy()
		dikiPod.Name = fmt.Sprintf("diki-%s-%s", v1r11.ID242446, "aaaaaaaaaa")
		dikiPod.Namespace = "kube-system"
		dikiPod.Labels = map[string]string{}

		Expect(fakeClient.Create(ctx, Node)).To(Succeed())
		Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubeAPIServerDep)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubeControllerManagerDep)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubeSchedulerDep)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubeAPIServerRS)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubeControllerManagerRS)).To(Succeed())
		Expect(fakeClient.Create(ctx, kubeSchedulerRS)).To(Succeed())
	})

	It("should fail when pods cannot be found", func() {
		fakePodContext = fakepod.NewFakeSimplePodContext([][]string{}, [][]error{})
		r := &v1r11.Rule242446{
			Logger:     testLogger,
			InstanceID: instanceID,
			Client:     fakeClient,
			Namespace:  Namespace,
			PodContext: fakePodContext,
		}

		ruleResult, err := r.Run(ctx)
		target := rule.NewTarget("namespace", r.Namespace)
		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			rule.FailedCheckResult("Pods not found!", target.With("name", "kube-apiserver", "kind", "Deployment", "namespace", r.Namespace)),
			rule.FailedCheckResult("Pods not found!", target.With("name", "kube-controller-manager", "kind", "Deployment", "namespace", r.Namespace)),
			rule.FailedCheckResult("Pods not found!", target.With("name", "kube-scheduler", "kind", "Deployment", "namespace", r.Namespace)),
		}))
	})

	It("should not only check selected deployments", func() {
		fakePodContext = fakepod.NewFakeSimplePodContext([][]string{}, [][]error{})
		r := &v1r11.Rule242446{
			Logger:          testLogger,
			InstanceID:      instanceID,
			Client:          fakeClient,
			Namespace:       Namespace,
			PodContext:      fakePodContext,
			DeploymentNames: []string{"kube-controller-manager", "kube-scheduler"},
		}

		ruleResult, err := r.Run(ctx)
		target := rule.NewTarget("namespace", r.Namespace)
		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			rule.FailedCheckResult("Pods not found!", target.With("name", "kube-controller-manager", "kind", "Deployment", "namespace", r.Namespace)),
			rule.FailedCheckResult("Pods not found!", target.With("name", "kube-scheduler", "kind", "Deployment", "namespace", r.Namespace)),
		}))
	})

	DescribeTable("Run cases",
		func(options *option.FileOwnerOptions, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			Expect(fakeClient.Create(ctx, kubeAPIServerPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeControllerManagerPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeSchedulerPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod)).To(Succeed())

			fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &v1r11.Rule242446{
				Logger:     testLogger,
				InstanceID: instanceID,
				Client:     fakeClient,
				Namespace:  Namespace,
				PodContext: fakePodContext,
				Options:    options,
			}

			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},
		Entry("should return passed checkResults when files have expected owners", nil,
			[][]string{{mounts, compliantStats, mounts, compliantStats2, emptyMounts}},
			[][]error{{nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-apiserver", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-apiserver", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-controller-manager", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file3.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-controller-manager", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file4.txt, ownerUser: 0, ownerGroup: 0")),
			}),
		Entry("should return failed checkResults when files have unexpected owners", nil,
			[][]string{{mounts, nonCompliantStats, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("name", "kube-apiserver", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.key, ownerGroup: 1000, expectedOwnerGroups: [0]")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("name", "kube-apiserver", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.key, ownerUser: 2000, expectedOwnerUsers: [0]")),
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
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-apiserver", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.key, ownerUser: 0, ownerGroup: 1000")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-apiserver", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.key, ownerUser: 2000, ownerGroup: 0")),
			}),
		Entry("should correctly return errored checkResults when commands error", nil,
			[][]string{{mounts, mounts, compliantStats2, emptyMounts}},
			[][]error{{errors.New("foo"), nil, errors.New("bar"), nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242446-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242446-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
			}),
		Entry("should check files when GetMountedFilesStats errors", nil,
			[][]string{{mountsMulty, compliantStats, emptyMounts, emptyMounts, emptyMounts, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, errors.New("bar"), nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242446-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-apiserver", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-apiserver", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.key, ownerUser: 0, ownerGroup: 0")),
			}),
		Entry("should correctly return all checkResults when commands error", nil,
			[][]string{{mounts, mounts, compliantStats2, emptyMounts}},
			[][]error{{errors.New("foo"), nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242446-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-controller-manager", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file3.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-controller-manager", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file4.txt, ownerUser: 0, ownerGroup: 0")),
			}),
	)
})
