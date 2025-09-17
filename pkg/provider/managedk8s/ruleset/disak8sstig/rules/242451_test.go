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
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	fakestrgen "github.com/gardener/diki/pkg/internal/stringgen/fake"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
	disaoption "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
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
		mountsMulti = `[
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
		kubeletPID            = "1"
		kubeletCommand        = "--config=var/lib/kubelet/config"
		kubeletCommandCert    = "--config=var/lib/kubelet/config --cert-dir"
		emptyMounts           = `[]`
		compliantStats        = "600\t0\t0\tregular file\t/destination/file1.key\n400\t0\t0\tregular file\t/destination/file2.pem"
		compliantKeyStats     = "644\t0\t0\tregular file\t/var/lib/keys/tls.key\n"
		compliantCertStats    = "644\t0\t0\tregular file\t/var/lib/certs/tls.crt\n"
		compliantDirStats     = "600\t0\t0\tdirectory\t/destination\n"
		compliantKeyDirStats  = "600\t0\t0\tdirectory\t/var/lib/keys\n"
		compliantCertDirStats = "600\t0\t0\tdirectory\t/var/lib/certs\n"
		compliantStats2       = "600\t0\t0\tregular file\t/destination/file3.crt\n600\t0\t0\tregular file\t/destination/file4.txt\n"
		noCrtKeyStats         = "600\t0\t0\tregular file\t/destination/file3.txt\n600\t1000\t0\tregular file\t/destination/file4.txt\n"
		nonCompliantStats     = "514\t1000\t0\tregular file\t/destination/file1.key\n700\t0\t2000\tregular file\t/destination/file2.pem\n"
		nonCompliantDirStats  = "600\t65532\t0\tdirectory\t/destination\n"
	)
	var (
		instanceID     = "1"
		fakeClient     client.Client
		fakePodContext pod.PodContext
		nodeName       = "node01"
		Node           *corev1.Node
		plainPod       *corev1.Pod
		kubeProxyPod1  *corev1.Pod
		kubeProxyPod2  *corev1.Pod
		fooPod         *corev1.Pod
		dikiPod1       *corev1.Pod
		dikiPod2       *corev1.Pod
		ctx            = context.TODO()
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

		kubeProxyPod1 = plainPod.DeepCopy()
		kubeProxyPod1.Name = "1-pod"
		kubeProxyPod1.Labels["role"] = "proxy"
		kubeProxyPod1.OwnerReferences = []metav1.OwnerReference{
			{
				UID:        "3",
				Name:       "deployment",
				Kind:       "Deployment",
				APIVersion: "apps/v1",
			},
		}

		kubeProxyPod2 = plainPod.DeepCopy()
		kubeProxyPod2.Name = "kube-proxy"
		kubeProxyPod2.Labels["role"] = "proxy"
		kubeProxyPod2.Labels["component"] = "kube-proxy"

		fooPod = plainPod.DeepCopy()
		fooPod.Name = "foo"

		dikiPod1 = plainPod.DeepCopy()
		dikiPod1.Name = fmt.Sprintf("diki-%s-%s", sharedrules.ID242451, "aaaaaaaaaa")
		dikiPod1.Namespace = "kube-system"
		dikiPod1.Labels = map[string]string{}
		dikiPod2 = plainPod.DeepCopy()
		dikiPod2.Name = fmt.Sprintf("diki-%s-%s", sharedrules.ID242451, "bbbbbbbbbb")
		dikiPod2.Namespace = "kube-system"
		dikiPod2.Labels = map[string]string{}
	})

	It("should fail when kube-proxy pods cannot be found", func() {
		fakePodContext = fakepod.NewFakeSimplePodContext([][]string{}, [][]error{})
		r := &rules.Rule242451{
			Logger:     testLogger,
			InstanceID: instanceID,
			Client:     fakeClient,
			PodContext: fakePodContext,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf([]rule.CheckResult{
			rule.ErroredCheckResult("kube-proxy pods not found", rule.NewTarget()),
			rule.ErroredCheckResult("no allocatable nodes could be selected", rule.NewTarget()),
		}))
	})

	DescribeTable("Run cases",
		func(options rules.Options242451, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			Expect(fakeClient.Create(ctx, Node)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeProxyPod1)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeProxyPod2)).To(Succeed())
			Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod1)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod2)).To(Succeed())

			fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &rules.Rule242451{
				Logger:     testLogger,
				InstanceID: instanceID,
				Client:     fakeClient,
				PodContext: fakePodContext,
				Options:    &options,
			}

			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
		},
		Entry("should return passed checkResults when files have expected owners", nil,
			[][]string{{kubeletPID, kubeletCommand, tlsKubeletConfig, compliantKeyStats, compliantCertStats, compliantKeyDirStats, compliantCertDirStats}, {mounts, compliantStats, compliantDirStats, mounts, compliantStats2, compliantDirStats}},
			[][]error{{nil, nil, nil, nil, nil, nil, nil}, {nil, nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file1.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file2.pem, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/file3.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/keys/tls.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/certs/tls.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/keys, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/certs, ownerUser: 0, ownerGroup: 0")),
			}),
		Entry("should return failed checkResults when files do not have expected owners", nil,
			[][]string{{kubeletPID, kubeletCommand, "", nonCompliantStats, nonCompliantDirStats}, {mounts, nonCompliantStats, nonCompliantDirStats, emptyMounts}},
			[][]error{{nil, nil, nil, nil, nil}, {nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file1.key, ownerUser: 1000, expectedOwnerUsers: [0]")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file2.pem, ownerGroup: 2000, expectedOwnerGroups: [0]")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination, ownerUser: 65532, expectedOwnerUsers: [0]")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /destination/file1.key, ownerUser: 1000, expectedOwnerUsers: [0]")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /destination/file2.pem, ownerGroup: 2000, expectedOwnerGroups: [0]")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /destination, ownerUser: 65532, expectedOwnerUsers: [0]")),
			}),
		Entry("should return failed checkResults when cert nor key files can be found in PKI dir", nil,
			[][]string{{kubeletPID, kubeletCommand, "", noCrtKeyStats}, {emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil}, {nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("no cert nor key files found in PKI directory", rule.NewTarget("name", "node01", "kind", "Node", "directory", "/var/lib/kubelet/pki")),
			}),
		Entry("should check only pod with matched labels",
			rules.Options242451{
				KubeProxy: disaoption.KubeProxyOptions{
					ClusterObjectSelector: &option.ClusterObjectSelector{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"component": "kube-proxy"},
						},
					},
				},
			},
			[][]string{{kubeletPID, kubeletCommand, tlsKubeletConfig, compliantKeyStats, compliantCertStats, compliantKeyDirStats, compliantCertDirStats}, {mounts, compliantStats, compliantDirStats}},
			[][]error{{nil, nil, nil, nil, nil, nil, nil}, {nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/file1.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/file2.pem, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/keys/tls.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/certs/tls.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/keys, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/certs, ownerUser: 0, ownerGroup: 0")),
			}),
		Entry("should check only nodes with labels",
			rules.Options242451{
				NodeGroupByLabels: []string{"foo"},
			},
			[][]string{{mounts, compliantStats, compliantDirStats, emptyMounts}},
			[][]error{{nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file1.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file2.pem, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination, ownerUser: 0, ownerGroup: 0")),
				rule.WarningCheckResult("Node is missing a label", rule.NewTarget("name", "node01", "kind", "Node", "label", "foo")),
				rule.ErroredCheckResult("no allocatable nodes could be selected", rule.NewTarget()),
			}),
		Entry("should return correct checkResults when file owner options are used",
			rules.Options242451{
				FileOwnerOptions: &disaoption.FileOwnerOptions{
					ExpectedFileOwner: disaoption.ExpectedOwner{
						Users:  []string{"0", "1000"},
						Groups: []string{"0", "2000"},
					},
				},
			},
			[][]string{{kubeletPID, kubeletCommand, "", nonCompliantStats, nonCompliantDirStats}, {mounts, nonCompliantStats, nonCompliantDirStats, emptyMounts}},
			[][]error{{nil, nil, nil, nil, nil}, {nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file1.key, ownerUser: 1000, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file2.pem, ownerUser: 0, ownerGroup: 2000")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination, ownerUser: 65532, expectedOwnerUsers: [0 1000]")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /destination/file1.key, ownerUser: 1000, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /destination/file2.pem, ownerUser: 0, ownerGroup: 2000")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /destination, ownerUser: 65532, expectedOwnerUsers: [0 1000]")),
			}),
		Entry("should return accepted check result when kubeProxyDisabled option is set to true",
			rules.Options242451{
				KubeProxy: disaoption.KubeProxyOptions{
					Disabled: true,
				},
			},
			[][]string{{kubeletPID, kubeletCommand, tlsKubeletConfig, compliantKeyStats, compliantCertStats, compliantKeyDirStats, compliantCertDirStats}},
			[][]error{{nil, nil, nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/keys/tls.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/certs/tls.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/keys, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/certs, ownerUser: 0, ownerGroup: 0")),
				rule.AcceptedCheckResult("kube-proxy check is skipped.", rule.NewTarget()),
			}),
		Entry("should correctly return errored checkResults when commands error", nil,
			[][]string{{kubeletPID}, {mounts, mounts, compliantStats2}},
			[][]error{{errors.New("foo-bar")}, {errors.New("foo"), nil, errors.New("bar")}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242451-bbbbbbbbbb", "namespace", "kube-system", "kind", "Pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242451-bbbbbbbbbb", "namespace", "kube-system", "kind", "Pod")),
				rule.ErroredCheckResult("foo-bar", rule.NewTarget("name", "diki-242451-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
			}),
		Entry("should check files when GetMountedFilesStats errors", nil,
			[][]string{{kubeletPID, kubeletCommandCert, ""},
				{mountsMulti, compliantStats, emptyMounts, compliantDirStats, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil}, {nil, nil, errors.New("bar"), nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242451-bbbbbbbbbb", "namespace", "kube-system", "kind", "Pod")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file1.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file2.pem, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination, ownerUser: 0, ownerGroup: 0")),
				rule.ErroredCheckResult("kubelet cert-dir flag set to empty", rule.NewTarget("name", "diki-242451-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
			}),
		Entry("should correctly return all checkResults when commands error", nil,
			[][]string{{kubeletPID, kubeletCommand, tlsKubeletConfig}, {mounts, mounts, compliantStats2, compliantDirStats}},
			[][]error{{nil, nil, errors.New("bar")}, {errors.New("foo"), nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242451-bbbbbbbbbb", "namespace", "kube-system", "kind", "Pod")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/file3.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination, ownerUser: 0, ownerGroup: 0")),
				rule.ErroredCheckResult("could not retrieve kubelet config: bar", rule.NewTarget("name", "diki-242451-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
			}),
	)
})
