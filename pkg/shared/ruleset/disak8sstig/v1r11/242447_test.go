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
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ = Describe("#242447", func() {
	const (
		kubeProxyConfig = `clientConnection:
  kubeconfig: /var/lib/kubeconfig2
`
		mounts = `[
  {
    "destination": "/var/lib/kubeconfig",
    "source": "/var/lib/kubeconfig"
  },
  {
    "destination": "/var/lib/config",
    "source": "/var/lib/config"
  },
  {
    "destination": "/var/lib/kubeconfig2",
    "source": "/var/lib/kubeconfig"
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
		emptyMounts                  = `[]`
		compliantConfigStats         = "644\t0\t0\tregular file\t/var/lib/config\n"
		nonCompliantConfigStats      = "664\t0\t0\tregular file\t/var/lib/config\n"
		compliantKubeconfigStats     = "600\t0\t0\tregular file\t/var/lib/kubeconfig\n"
		compliantKubeconfigStats2    = "600\t0\t0\tregular file\t/var/lib/kubeconfig2\n"
		nonCompliantKubeconfigStats  = "700\t0\t0\tregular file\t/var/lib/kubeconfig\n"
		nonCompliantKubeconfigStats2 = "606\t0\t0\tregular file\t/var/lib/kubeconfig2\n"
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
		kubeProxyPod3  *corev1.Pod
		fooPod         *corev1.Pod
		dikiPod        *corev1.Pod
		ctx            = context.TODO()
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

		plainPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Labels:    map[string]string{},
				Namespace: "kube-system",
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind: "Node",
					},
				},
			},
			Spec: corev1.PodSpec{
				NodeName: nodeName,
				Containers: []corev1.Container{
					{
						Name: "kube-proxy",
					},
				},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:        "kube-proxy",
						ContainerID: "containerd://bar",
					},
				},
			},
		}

		kubeProxyPod1 = plainPod.DeepCopy()
		kubeProxyPod1.Name = "1-pod"
		kubeProxyPod1.Labels["role"] = "proxy"
		kubeProxyPod1.Labels["component"] = "kube-proxy"
		kubeProxyPod1.Spec.Containers[0].Command = []string{"--config=/var/lib/config", "--kubeconfig=/var/lib/kubeconfig"}
		kubeProxyPod1.OwnerReferences[0].UID = "1"

		kubeProxyPod2 = plainPod.DeepCopy()
		kubeProxyPod2.Name = "2-pod"
		kubeProxyPod2.Labels["role"] = "proxy"
		kubeProxyPod2.Spec.Containers[0].Command = []string{"--config=/var/lib/config"}
		kubeProxyPod2.OwnerReferences[0].UID = "2"

		kubeProxyPod3 = plainPod.DeepCopy()
		kubeProxyPod3.Name = "3-pod"
		kubeProxyPod3.Labels["role"] = "proxy"
		kubeProxyPod3.Spec.Containers[0].Command = []string{"--kubeconfig=/var/lib/kubeconfig"}
		kubeProxyPod3.OwnerReferences[0].UID = "1"

		fooPod = plainPod.DeepCopy()
		fooPod.Name = "foo"

		dikiPod = plainPod.DeepCopy()
		dikiPod.Name = fmt.Sprintf("diki-%s-%s", v1r11.ID242447, "aaaaaaaaaa")
		dikiPod.Labels = map[string]string{}
	})

	It("should fail when kube-proxy pods cannot be found", func() {
		Expect(fakeClient.Create(ctx, Node)).To(Succeed())
		Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())
		kubeProxySelector := labels.SelectorFromSet(labels.Set{"role": "proxy"})
		fakePodContext = fakepod.NewFakeSimplePodContext([][]string{}, [][]error{})
		r := &v1r11.Rule242447{
			Logger:     testLogger,
			InstanceID: instanceID,
			Client:     fakeClient,
			PodContext: fakePodContext,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			rule.FailedCheckResult("Kube-proxy pods not found!", rule.NewTarget("selector", kubeProxySelector.String())),
		}))
	})

	DescribeTable("Run cases",
		func(options v1r11.Options242447, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			Expect(fakeClient.Create(ctx, Node)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeProxyPod1)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeProxyPod2)).To(Succeed())
			Expect(fakeClient.Create(ctx, kubeProxyPod3)).To(Succeed())
			Expect(fakeClient.Create(ctx, fooPod)).To(Succeed())
			Expect(fakeClient.Create(ctx, dikiPod)).To(Succeed())

			fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &v1r11.Rule242447{
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
			[][]string{{mounts, compliantConfigStats, compliantKubeconfigStats, mounts, compliantConfigStats, kubeProxyConfig, compliantKubeconfigStats2}},
			[][]error{{nil, nil, nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /var/lib/config, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /var/lib/kubeconfig, permissions: 600")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "2-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /var/lib/config, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "2-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /var/lib/kubeconfig2, permissions: 600")),
			}),
		Entry("should return failed checkResults when files have too wide permissions", nil,
			[][]string{{mounts, nonCompliantConfigStats, nonCompliantKubeconfigStats, mounts, nonCompliantConfigStats, kubeProxyConfig, nonCompliantKubeconfigStats2}},
			[][]error{{nil, nil, nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "1-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /var/lib/config, permissions: 664, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "1-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /var/lib/kubeconfig, permissions: 700, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "2-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /var/lib/config, permissions: 664, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("name", "2-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /var/lib/kubeconfig2, permissions: 606, expectedPermissionsMax: 644")),
			}),
		Entry("should return warning when kubeconfig is created by token", nil,
			[][]string{{mounts, compliantConfigStats, compliantKubeconfigStats, mounts, compliantConfigStats, ""}},
			[][]error{{nil, nil, nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /var/lib/config, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("name", "1-pod", "namespace", "kube-system", "kind", "pod", "details", "fileName: /var/lib/kubeconfig, permissions: 600")),
				rule.WarningCheckResult("Kube-proxy creates kubeconfig using serviceaccount token!", rule.NewTarget("name", "2-pod", "namespace", "kube-system", "kind", "pod")),
			}),
		Entry("should return correct errors when mounts and config stats commands fail", nil,
			[][]string{{mounts, mounts, compliantConfigStats}},
			[][]error{{errors.New("foo"), nil, errors.New("bar")}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242447-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242447-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
			}),
		Entry("should return correct errors when kubeconfig stats and kubeConfig commands fail", nil,
			[][]string{{mounts, compliantConfigStats, compliantKubeconfigStats, mounts, compliantConfigStats, kubeProxyConfig}},
			[][]error{{nil, nil, errors.New("foo"), nil, errors.New("bar")}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242447-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242447-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
			}),
	)
})
