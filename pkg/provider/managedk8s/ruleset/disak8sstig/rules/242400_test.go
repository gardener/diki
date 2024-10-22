// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	manualfake "k8s.io/client-go/rest/fake"
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

var _ = Describe("#242400", func() {
	const (
		allowedKubeProxyConfig = `featureGates:
  AllAlpha: false
`
		notAllowedKubeProxyConfig = `featureGates:
  AllAlpha: true
`
		mounts = `[
  {
    "destination": "/var/lib/config",
    "source": "/var/lib/config"
  }
]`
		podSecurityAllowedNodeConfig    = `{"kubeletconfig":{"featureGates":{"AllAlpha":false}}}`
		podSecurityNotAllowedNodeConfig = `{"kubeletconfig":{"featureGates":{"AllAlpha":true}}}`
		podSecurityNotSetNodeConfig     = `{"kubeletconfig":{"authentication":{"webhook":{"enabled":true,"cacheTTL":"2m0s"}}}}`
	)

	var (
		instanceID     = "1"
		fakeClient     client.Client
		fakePodContext pod.PodContext
		fakeRESTClient rest.Interface
		plainNode      *corev1.Node
		plainPod       *corev1.Pod
		dikiPod        *corev1.Pod
		ctx            = context.TODO()
	)

	BeforeEach(func() {
		sharedrules.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
		fakeClient = fakeclient.NewClientBuilder().Build()

		plainNode = &corev1.Node{
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{
						Type:   corev1.NodeReady,
						Status: corev1.ConditionTrue,
					},
				},
				Allocatable: corev1.ResourceList{
					"pods": resource.MustParse("100.0"),
				},
			},
		}

		plainPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"role": "proxy",
				},
				Namespace: "kube-system",
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind: "Node",
					},
				},
			},
			Spec: corev1.PodSpec{
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

		dikiPod = plainPod.DeepCopy()
		dikiPod.Name = fmt.Sprintf("diki-%s-%s", sharedrules.ID242400, "aaaaaaaaaa")
		dikiPod.Labels = map[string]string{}
		Expect(fakeClient.Create(ctx, dikiPod)).To(Succeed())
	})

	It("should return correct checkResults", func() {
		node1 := plainNode.DeepCopy()
		node1.ObjectMeta.Name = "node1"
		Expect(fakeClient.Create(ctx, node1)).To(Succeed())

		node2 := plainNode.DeepCopy()
		node2.ObjectMeta.Name = "node2"
		Expect(fakeClient.Create(ctx, node2)).To(Succeed())

		node3 := plainNode.DeepCopy()
		node3.ObjectMeta.Name = "node3"
		Expect(fakeClient.Create(ctx, node3)).To(Succeed())

		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.OwnerReferences[0].UID = "1"
		pod1.Spec.NodeName = "node1"
		pod1.Spec.Containers[0].Command = []string{"--flag1=value1", "--flag2=value2"}
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.OwnerReferences[0].UID = "2"
		pod2.Spec.NodeName = "node1"
		pod2.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=true"}
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		pod3 := plainPod.DeepCopy()
		pod3.Name = "pod3"
		pod3.OwnerReferences[0].UID = "3"
		pod3.Spec.NodeName = "node1"
		pod3.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=false"}
		Expect(fakeClient.Create(ctx, pod3)).To(Succeed())

		pod4 := plainPod.DeepCopy()
		pod4.Name = "pod4"
		pod4.OwnerReferences[0].UID = "4"
		pod4.Spec.NodeName = "node1"
		pod4.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=true", "--config=/var/lib/config"}
		Expect(fakeClient.Create(ctx, pod4)).To(Succeed())

		pod5 := plainPod.DeepCopy()
		pod5.Name = "pod5"
		pod5.OwnerReferences[0].UID = "5"
		pod5.Spec.NodeName = "node1"
		pod5.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=true", "--config=/var/lib/config"}
		Expect(fakeClient.Create(ctx, pod5)).To(Succeed())

		pod6 := plainPod.DeepCopy()
		pod6.Name = "pod6"
		pod6.OwnerReferences[0].UID = "6"
		pod6.Spec.NodeName = "node1"
		pod6.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=true", "--config=/var/lib/config"}
		Expect(fakeClient.Create(ctx, pod6)).To(Succeed())

		pod7 := plainPod.DeepCopy()
		pod7.Name = "pod7"
		pod7.OwnerReferences[0].UID = "7"
		pod7.Spec.NodeName = "node1"
		pod7.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=true", "--feature-gates=AllAlpha=false"}
		Expect(fakeClient.Create(ctx, pod7)).To(Succeed())

		pod8 := plainPod.DeepCopy()
		pod8.Name = "pod8"
		pod8.OwnerReferences[0].UID = "8"
		pod8.Spec.NodeName = "node1"
		pod8.Spec.Containers[0].Command = []string{"--flag1=value1", "--config=/var/lib/config", "--config=/var/lib/config2"}
		Expect(fakeClient.Create(ctx, pod8)).To(Succeed())

		fakeRESTClient = &manualfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
			NegotiatedSerializer: scheme.Codecs,
			Client: manualfake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
				switch req.URL.String() {
				case "https://localhost/nodes/node1/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(podSecurityAllowedNodeConfig)))}, nil
				case "https://localhost/nodes/node2/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(podSecurityNotAllowedNodeConfig)))}, nil
				case "https://localhost/nodes/node3/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(podSecurityNotSetNodeConfig)))}, nil
				default:
					return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(&bytes.Buffer{})}, nil
				}
			}),
		}

		executeReturnStrings := [][]string{{mounts, allowedKubeProxyConfig, mounts, notAllowedKubeProxyConfig, mounts, ""}}
		executeReturnErrors := [][]error{{nil, nil, nil, nil, nil, nil}}
		fakePodContext = fakepod.NewFakeSimplePodContext(executeReturnStrings, executeReturnErrors)
		r := &rules.Rule242400{
			InstanceID:   instanceID,
			Client:       fakeClient,
			PodContext:   fakePodContext,
			V1RESTClient: fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("kind", "pod", "name", "pod1", "namespace", "kube-system")),
			rule.FailedCheckResult("Option featureGates.AllAlpha set to not allowed value.", rule.NewTarget("kind", "pod", "name", "pod2", "namespace", "kube-system")),
			rule.PassedCheckResult("Option featureGates.AllAlpha set to allowed value.", rule.NewTarget("kind", "pod", "name", "pod3", "namespace", "kube-system")),
			rule.PassedCheckResult("Option featureGates.AllAlpha set to allowed value.", rule.NewTarget("kind", "pod", "name", "pod4", "namespace", "kube-system")),
			rule.FailedCheckResult("Option featureGates.AllAlpha set to not allowed value.", rule.NewTarget("kind", "pod", "name", "pod5", "namespace", "kube-system")),
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("kind", "pod", "name", "pod6", "namespace", "kube-system")),
			rule.WarningCheckResult("Option featureGates.AllAlpha set more than once in container command.", rule.NewTarget("kind", "pod", "name", "pod7", "namespace", "kube-system")),
			rule.ErroredCheckResult("option config set more than once in container command", rule.NewTarget("kind", "pod", "name", "pod8", "namespace", "kube-system")),
			rule.PassedCheckResult("Option featureGates.AllAlpha set to allowed value.", rule.NewTarget("kind", "node", "name", "node1")),
			rule.FailedCheckResult("Option featureGates.AllAlpha set to not allowed value.", rule.NewTarget("kind", "node", "name", "node2")),
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("kind", "node", "name", "node3")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should check correct pods when options are used", func() {
		node1 := plainNode.DeepCopy()
		node1.ObjectMeta.Name = "node1"
		Expect(fakeClient.Create(ctx, node1)).To(Succeed())

		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.Labels["foo"] = "bar"
		pod1.OwnerReferences[0].UID = "1"
		pod1.Spec.NodeName = "node1"
		pod1.Spec.Containers[0].Command = []string{"--flag1=value1", "--flag2=value2"}
		Expect(fakeClient.Create(ctx, pod1)).To(Succeed())

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.OwnerReferences[0].UID = "2"
		pod2.Spec.NodeName = "node1"
		pod2.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=true"}
		Expect(fakeClient.Create(ctx, pod2)).To(Succeed())

		pod3 := plainPod.DeepCopy()
		pod3.Name = "pod3"
		pod3.Labels["foo"] = "bar"
		pod3.OwnerReferences[0].UID = "3"
		pod3.Spec.NodeName = "node1"
		pod3.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=false"}
		Expect(fakeClient.Create(ctx, pod3)).To(Succeed())

		options := rules.Options242400{
			KubeProxyMatchLabels: map[string]string{
				"foo": "bar",
			},
		}

		fakeRESTClient = &manualfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
			NegotiatedSerializer: scheme.Codecs,
			Client: manualfake.CreateHTTPClient(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(podSecurityNotSetNodeConfig)))}, nil
			}),
		}

		fakePodContext = fakepod.NewFakeSimplePodContext([][]string{{}}, [][]error{{}})
		r := &rules.Rule242400{
			InstanceID:   instanceID,
			Client:       fakeClient,
			PodContext:   fakePodContext,
			V1RESTClient: fakeRESTClient,
			Options:      &options,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("kind", "pod", "name", "pod1", "namespace", "kube-system")),
			rule.PassedCheckResult("Option featureGates.AllAlpha set to allowed value.", rule.NewTarget("kind", "pod", "name", "pod3", "namespace", "kube-system")),
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("kind", "node", "name", "node1")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should correctly find the kube-proxy container", func() {
		node1 := plainNode.DeepCopy()
		node1.ObjectMeta.Name = "node1"
		Expect(fakeClient.Create(ctx, node1)).To(Succeed())

		kubeProxyContainerPod := plainPod.DeepCopy()
		kubeProxyContainerPod.Name = "kube-proxy-container-pod"
		kubeProxyContainerPod.Spec.NodeName = "node1"
		kubeProxyContainerPod.Spec.Containers[0].Command = []string{"--flag1=value1", "--flag2=value2"}
		kubeProxyContainerPod.OwnerReferences[0].UID = "1"
		Expect(fakeClient.Create(ctx, kubeProxyContainerPod)).To(Succeed())

		proxyContainerPod := plainPod.DeepCopy()
		proxyContainerPod.Name = "proxy-container-pod"
		proxyContainerPod.Spec.NodeName = "node1"
		proxyContainerPod.Spec.Containers[0].Name = "proxy"
		proxyContainerPod.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=true"}
		proxyContainerPod.OwnerReferences[0].UID = "2"
		Expect(fakeClient.Create(ctx, proxyContainerPod)).To(Succeed())

		nonValidContainerPod := plainPod.DeepCopy()
		nonValidContainerPod.Name = "non-valid-container-pod"
		nonValidContainerPod.Spec.NodeName = "node1"
		nonValidContainerPod.Spec.Containers[0].Name = "foo"
		nonValidContainerPod.Spec.Containers[0].Command = []string{"--flag1=value1", "--config=/var/lib/config"}
		nonValidContainerPod.OwnerReferences[0].UID = "3"
		Expect(fakeClient.Create(ctx, nonValidContainerPod)).To(Succeed())

		fakeRESTClient = &manualfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
			NegotiatedSerializer: scheme.Codecs,
			Client: manualfake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
				switch req.URL.String() {
				case "https://localhost/nodes/node1/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(podSecurityAllowedNodeConfig)))}, nil
				default:
					return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(&bytes.Buffer{})}, nil
				}
			}),
		}

		fakePodContext = fakepod.NewFakeSimplePodContext([][]string{{}}, [][]error{{}})
		r := &rules.Rule242400{
			Logger:       testLogger,
			InstanceID:   instanceID,
			Client:       fakeClient,
			V1RESTClient: fakeRESTClient,
			PodContext:   fakePodContext,
		}

		ruleResult, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedResults := []rule.CheckResult{
			rule.PassedCheckResult("Option featureGates.AllAlpha set to allowed value.", rule.NewTarget("kind", "node", "name", "node1")),
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("name", "kube-proxy-container-pod", "namespace", "kube-system", "kind", "pod")),
			rule.ErroredCheckResult("Pod does not contain any of the containers specified in the provided list: [kube-proxy proxy]", rule.NewTarget("name", "non-valid-container-pod", "namespace", "kube-system", "kind", "pod")),
			rule.FailedCheckResult("Option featureGates.AllAlpha set to not allowed value.", rule.NewTarget("name", "proxy-container-pod", "namespace", "kube-system", "kind", "pod")),
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedResults))
	})

	It("should error when kube-proxy pods cannot be found", func() {
		node1 := plainNode.DeepCopy()
		node1.ObjectMeta.Name = "node1"
		Expect(fakeClient.Create(ctx, node1)).To(Succeed())

		fakeRESTClient = &manualfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
			NegotiatedSerializer: scheme.Codecs,
			Client: manualfake.CreateHTTPClient(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(podSecurityNotSetNodeConfig)))}, nil
			}),
		}
		r := &rules.Rule242400{
			InstanceID:   instanceID,
			Client:       fakeClient,
			PodContext:   fakePodContext,
			V1RESTClient: fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.ErroredCheckResult("kube-proxy pods not found", rule.NewTarget("selector", "role=proxy")),
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("kind", "node", "name", "node1")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return accepted check result when kubeProxyDiabled option is set to true", func() {
		node1 := plainNode.DeepCopy()
		node1.ObjectMeta.Name = "node1"
		Expect(fakeClient.Create(ctx, node1)).To(Succeed())

		fakeRESTClient = &manualfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
			NegotiatedSerializer: scheme.Codecs,
			Client: manualfake.CreateHTTPClient(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(podSecurityNotSetNodeConfig)))}, nil
			}),
		}
		r := &rules.Rule242400{
			InstanceID:   instanceID,
			Client:       fakeClient,
			PodContext:   fakePodContext,
			V1RESTClient: fakeRESTClient,
			Options: &rules.Options242400{
				KubeProxyOptions: option.KubeProxyOptions{
					KubeProxyDisabled: true,
				},
			},
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.AcceptedCheckResult("kube-proxy check is skipped.", rule.NewTarget()),
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("kind", "node", "name", "node1")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return warn when nodes are not found", func() {
		fakeRESTClient = &manualfake.RESTClient{}
		r := &rules.Rule242400{
			Client:       fakeClient,
			V1RESTClient: fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.WarningCheckResult("No nodes found.", rule.NewTarget()),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})
})
