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
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#242467", func() {
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
		kubeletPID         = "1"
		kubeletCommand     = "--config=var/lib/kubelet/config"
		kubeletCommandCert = "--config=var/lib/kubelet/config --cert-dir"
		emptyMounts        = `[]`
		compliantStats     = "600\t0\t0\tregular file\t/destination/file1.key\n400\t0\t65532\tregular file\t/destination/bar/file2.pem"
		compliantKeyStats  = "640\t0\t0\tregular file\t/var/lib/keys/tls.key\n"
		compliantStats2    = "600\t0\t0\tregular file\t/destination/file3.key\n600\t1000\t0\tregular file\t/destination/bar/file4.txt\n"
		noKeyStats         = "600\t0\t0\tregular file\t/destination/file3.txt\n600\t1000\t0\tregular file\t/destination/bar/file4.txt\n"
		nonCompliantStats  = "644\t0\t0\tregular file\t/destination/file1.key\n700\t0\t0\tregular file\t/destination/bar/file2.pem\n"
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
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       "deployment",
			},
		}

		kubeProxyPod2 = plainPod.DeepCopy()
		kubeProxyPod2.Name = "kube-proxy"
		kubeProxyPod2.Labels["role"] = "proxy"
		kubeProxyPod2.Labels["component"] = "kube-proxy"

		fooPod = plainPod.DeepCopy()
		fooPod.Name = "foo"

		dikiPod1 = plainPod.DeepCopy()
		dikiPod1.Name = fmt.Sprintf("diki-%s-%s", sharedrules.ID242467, "aaaaaaaaaa")
		dikiPod1.Namespace = "kube-system"
		dikiPod1.Labels = map[string]string{}
		dikiPod2 = plainPod.DeepCopy()
		dikiPod2.Name = fmt.Sprintf("diki-%s-%s", sharedrules.ID242467, "bbbbbbbbbb")
		dikiPod2.Namespace = "kube-system"
		dikiPod2.Labels = map[string]string{}
	})

	It("should fail when etcd pods cannot be found", func() {
		kubeProxySelector := labels.SelectorFromSet(labels.Set{"role": "proxy"})
		fakePodContext = fakepod.NewFakeSimplePodContext([][]string{}, [][]error{})
		r := &rules.Rule242467{
			Logger:     testLogger,
			InstanceID: instanceID,
			Client:     fakeClient,
			PodContext: fakePodContext,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf([]rule.CheckResult{
			rule.ErroredCheckResult("pods not found", rule.NewTarget("selector", kubeProxySelector.String())),
			rule.ErroredCheckResult("no allocatable nodes could be selected", rule.NewTarget()),
		}))
	})

	DescribeTable("Run cases",
		func(options rules.Options242467, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			Expect(fakeClient.Create(ctx, Node)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeProxyPod1)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeProxyPod2)).To(Succeed())
			Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod1)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod2)).To(Succeed())

			fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &rules.Rule242467{
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
		Entry("should return passed checkResults when files have expected permissions", nil,
			[][]string{{kubeletPID, kubeletCommand, tlsKubeletConfig, compliantKeyStats}, {mounts, compliantStats, mounts, compliantStats2}},
			[][]error{{nil, nil, nil, nil}, {nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file1.key, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/file3.key, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/keys/tls.key, permissions: 640")),
			}),
		Entry("should return failed checkResults when files have too wide permissions", nil,
			[][]string{{kubeletPID, kubeletCommand, "", nonCompliantStats}, {mounts, nonCompliantStats, emptyMounts}},
			[][]error{{nil, nil, nil, nil}, {nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file1.key, permissions: 644, expectedPermissionsMax: 640")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/bar/file2.pem, permissions: 700, expectedPermissionsMax: 640")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /destination/file1.key, permissions: 644, expectedPermissionsMax: 640")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /destination/bar/file2.pem, permissions: 700, expectedPermissionsMax: 640")),
			}),
		Entry("should return failed checkResults when key files cannot be found in PKI dir", nil,
			[][]string{{kubeletPID, kubeletCommand, "", noKeyStats}, {emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil}, {nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("no '.key' files found in PKI directory", rule.NewTarget("name", "node01", "kind", "Node", "directory", "/var/lib/kubelet/pki")),
			}),
		Entry("should check only pod with matched labels",
			rules.Options242467{
				KubeProxyMatchLabels: map[string]string{
					"component": "kube-proxy",
				},
			},
			[][]string{{kubeletPID, kubeletCommand, tlsKubeletConfig, compliantKeyStats}, {mounts, compliantStats}},
			[][]error{{nil, nil, nil, nil}, {nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/file1.key, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/keys/tls.key, permissions: 640")),
			}),
		Entry("should return accepted check result when kubeProxyDisabled option is set to true",
			rules.Options242467{
				KubeProxyOptions: option.KubeProxyOptions{
					KubeProxyDisabled: true,
				},
			},
			[][]string{{kubeletPID, kubeletCommand, tlsKubeletConfig, compliantKeyStats}},
			[][]error{{nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.AcceptedCheckResult("kube-proxy check is skipped.", rule.NewTarget()),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "node01", "kind", "Node", "details", "fileName: /var/lib/keys/tls.key, permissions: 640")),
			}),
		Entry("should check only nodes with labels",
			rules.Options242467{
				NodeGroupByLabels: []string{"foo"},
			},
			[][]string{{mounts, compliantStats, emptyMounts}},
			[][]error{{nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file1.key, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
				rule.WarningCheckResult("Node is missing a label", rule.NewTarget("name", "node01", "kind", "Node", "label", "foo")),
				rule.ErroredCheckResult("no allocatable nodes could be selected", rule.NewTarget()),
			}),
		Entry("should correctly return errored checkResults when commands error", nil,
			[][]string{{kubeletPID}, {mounts, mounts, compliantStats2}},
			[][]error{{errors.New("foo-bar")}, {errors.New("foo"), nil, errors.New("bar")}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242467-bbbbbbbbbb", "namespace", "kube-system", "kind", "Pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242467-bbbbbbbbbb", "namespace", "kube-system", "kind", "Pod")),
				rule.ErroredCheckResult("foo-bar", rule.NewTarget("name", "diki-242467-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
			}),
		Entry("should check files when GetMountedFilesStats errors", nil,
			[][]string{{kubeletPID, kubeletCommandCert, "", compliantKeyStats},
				{mountsMulti, compliantStats, emptyMounts, emptyMounts}},
			[][]error{{nil, nil, nil, nil}, {nil, nil, errors.New("bar"), nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242467-bbbbbbbbbb", "namespace", "kube-system", "kind", "Pod")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/file1.key, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "deployment", "namespace", "foo", "containerName", "test", "kind", "Deployment", "details", "fileName: /destination/bar/file2.pem, permissions: 400")),
				rule.ErroredCheckResult("kubelet cert-dir flag set to empty", rule.NewTarget("name", "diki-242467-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
			}),
		Entry("should correctly return all checkResults when commands error", nil,
			[][]string{{kubeletPID, kubeletCommand, tlsKubeletConfig}, {mounts, mounts, compliantStats2}},
			[][]error{{nil, nil, errors.New("bar")}, {errors.New("foo"), nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242467-bbbbbbbbbb", "namespace", "kube-system", "kind", "Pod")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "Pod", "details", "fileName: /destination/file3.key, permissions: 600")),
				rule.ErroredCheckResult("could not retrieve kubelet config: bar", rule.NewTarget("name", "diki-242467-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
			}),
	)
})
