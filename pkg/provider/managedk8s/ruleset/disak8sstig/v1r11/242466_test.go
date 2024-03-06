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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	fakestrgen "github.com/gardener/diki/pkg/internal/stringgen/fake"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
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
		compliantStats     = "600\t0\t0\tregular file\t/destination/file1.crt\n400\t0\t65532\tregular file\t/destination/bar/file2.crt"
		compliantCertStats = "644\t0\t0\tregular file\t/var/lib/certs/tls.crt\n"
		compliantStats2    = "600\t0\t0\tregular file\t/destination/file3.crt\n600\t1000\t0\tregular file\t/destination/bar/file4.txt\n"
		noCrtStats         = "600\t0\t0\tregular file\t/destination/file3.txt\n600\t1000\t0\tregular file\t/destination/bar/file4.txt\n"
		nonCompliantStats  = "664\t0\t0\tregular file\t/destination/file1.crt\n700\t0\t0\tregular file\t/destination/bar/file2.crt\n"
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
		dikiPod        *corev1.Pod
		ctx            = context.TODO()
	)

	BeforeEach(func() {
		sharedv1r11.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
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

		kubeProxyPod2 = plainPod.DeepCopy()
		kubeProxyPod2.Name = "kube-proxy"
		kubeProxyPod2.Labels["role"] = "proxy"
		kubeProxyPod2.Labels["component"] = "kube-proxy"

		fooPod = plainPod.DeepCopy()
		fooPod.Name = "foo"

		dikiPod = plainPod.DeepCopy()
		dikiPod.Name = fmt.Sprintf("diki-%s-%s", sharedv1r11.ID242466, "aaaaaaaaaa")
		dikiPod.Namespace = "kube-system"
		dikiPod.Labels = map[string]string{}
	})

	It("should fail when etcd pods cannot be found", func() {
		kubeProxySelector := labels.SelectorFromSet(labels.Set{"role": "proxy"})
		fakePodContext = fakepod.NewFakeSimplePodContext([][]string{}, [][]error{})
		r := &v1r11.Rule242466{
			Logger:     testLogger,
			InstanceID: instanceID,
			Client:     fakeClient,
			PodContext: fakePodContext,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			rule.FailedCheckResult("Pods not found!", rule.NewTarget("selector", kubeProxySelector.String())),
			rule.ErroredCheckResult("no allocatable nodes could be selected", rule.NewTarget()),
		}))
	})

	DescribeTable("Run cases",
		func(options v1r11.Options242466, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			Expect(fakeClient.Create(ctx, Node)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeProxyPod1)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeProxyPod2)).To(Succeed())
			Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod)).To(Succeed())

			fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &v1r11.Rule242466{
				Logger:     testLogger,
				InstanceID: instanceID,
				Client:     fakeClient,
				PodContext: fakePodContext,
				Options:    &options,
			}

			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},
		Entry("should return passed checkResults when files have expected permissions", nil,
			[][]string{{mounts, compliantStats, mounts, compliantStats2}, {kubeletPID, kubeletCommand, tlsKubeletConfig, compliantCertStats}},
			[][]error{{nil, nil, nil, nil}, {nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.crt, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file3.crt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "node01", "kind", "node", "details", "fileName: /var/lib/certs/tls.crt, permissions: 644")),
			}),
		Entry("should return failed checkResults when files have too wide permissions", nil,
			[][]string{{mounts, nonCompliantStats, emptyMounts}, {kubeletPID, kubeletCommand, "", nonCompliantStats}},
			[][]error{{nil, nil, nil}, {nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 664, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.crt, permissions: 700, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "node01", "kind", "node", "details", "fileName: /destination/file1.crt, permissions: 664, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "node01", "kind", "node", "details", "fileName: /destination/bar/file2.crt, permissions: 700, expectedPermissionsMax: 644")),
			}),
		Entry("should return failed checkResults when crt files cannot be found in PKI dir", nil,
			[][]string{{emptyMounts, emptyMounts}, {kubeletPID, kubeletCommand, "", noCrtStats}},
			[][]error{{nil, nil}, {nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("no '.crt' files found in PKI directory", rule.NewTarget("name", "node01", "kind", "node", "directory", "/var/lib/kubelet/pki")),
			}),
		Entry("should check only pod with matched labels",
			v1r11.Options242466{
				PodMatchLabels: map[string]string{
					"component": "kube-proxy",
				},
			},
			[][]string{{mounts, compliantStats}, {kubeletPID, kubeletCommand, tlsKubeletConfig, compliantCertStats}},
			[][]error{{nil, nil}, {nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.crt, permissions: 400")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "node01", "kind", "node", "details", "fileName: /var/lib/certs/tls.crt, permissions: 644")),
			}),
		Entry("should check only nodes wtih labels",
			v1r11.Options242466{
				GroupByLabels: []string{"foo"},
			},
			[][]string{{mounts, compliantStats, emptyMounts}},
			[][]error{{nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.crt, permissions: 400")),
				rule.WarningCheckResult("Node is missing a label", rule.NewTarget("name", "node01", "kind", "node", "label", "foo")),
				rule.ErroredCheckResult("no allocatable nodes could be selected", rule.NewTarget()),
			}),
		Entry("should correctly return errored checkResults when commands error", nil,
			[][]string{{mounts, mounts, compliantStats2}, {kubeletPID}},
			[][]error{{errors.New("foo"), nil, errors.New("bar")}, {errors.New("foo-bar")}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242466-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242466-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("foo-bar", rule.NewTarget("name", "diki-242466-bbbbbbbbbb", "namespace", "kube-system", "kind", "pod")),
			}),
		Entry("should check files when GetMountedFilesStats errors", nil,
			[][]string{{mountsMulty, compliantStats, emptyMounts, emptyMounts},
				{kubeletPID, kubeletCommandCert, "", compliantCertStats}},
			[][]error{{nil, nil, errors.New("bar"), nil, nil}, {nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242466-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file1.crt, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/bar/file2.crt, permissions: 400")),
				rule.ErroredCheckResult("kubelet cert-dir flag set to empty", rule.NewTarget("name", "diki-242466-bbbbbbbbbb", "namespace", "kube-system", "kind", "pod")),
			}),
		Entry("should correctly return all checkResults when commands error", nil,
			[][]string{{mounts, mounts, compliantStats2}, {kubeletPID, kubeletCommand, tlsKubeletConfig}},
			[][]error{{errors.New("foo"), nil, nil}, {nil, nil, errors.New("bar")}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242466-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "kube-proxy", "namespace", "foo", "containerName", "test", "kind", "pod", "details", "fileName: /destination/file3.crt, permissions: 600")),
				rule.ErroredCheckResult("could not retrieve kubelet config: bar", rule.NewTarget("name", "diki-242466-bbbbbbbbbb", "namespace", "kube-system", "kind", "pod")),
			}),
	)
})
