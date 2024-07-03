// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
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
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
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
		instanceID             = "1"
		controlPlaneNamespace  = "foo"
		fakePodContext         pod.PodContext
		fakeControlPlaneClient client.Client
		fakeClusterClient      client.Client
		fakeRESTClient         rest.Interface
		plainNode              *corev1.Node
		plainDeployment        *appsv1.Deployment
		kapiDeployment         *appsv1.Deployment
		kcmDeployment          *appsv1.Deployment
		ksDeployment           *appsv1.Deployment
		plainPod               *corev1.Pod
		dikiPod                *corev1.Pod
		ctx                    = context.TODO()
	)

	BeforeEach(func() {
		sharedv1r11.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
		fakeClusterClient = fakeclient.NewClientBuilder().Build()
		fakeControlPlaneClient = fakeclient.NewClientBuilder().Build()

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

		plainDeployment = &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: controlPlaneNamespace,
			},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Command: []string{},
								Args:    []string{},
							},
						},
					},
				},
			},
		}

		kapiDeployment = plainDeployment.DeepCopy()
		kapiDeployment.Name = "kube-apiserver"
		kapiDeployment.Spec.Template.Spec.Containers[0].Name = "kube-apiserver"

		kcmDeployment = plainDeployment.DeepCopy()
		kcmDeployment.Name = "kube-controller-manager"
		kcmDeployment.Spec.Template.Spec.Containers[0].Name = "kube-controller-manager"

		ksDeployment = plainDeployment.DeepCopy()
		ksDeployment.Name = "kube-scheduler"
		ksDeployment.Spec.Template.Spec.Containers[0].Name = "kube-scheduler"

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
		dikiPod.Name = fmt.Sprintf("diki-%s-%s", sharedv1r11.ID242400, "aaaaaaaaaa")
		dikiPod.Labels = map[string]string{}
		Expect(fakeClusterClient.Create(ctx, dikiPod)).To(Succeed())
	})

	It("should return correct checkResults", func() {
		kapiDeployment.Spec.Template.Spec.Containers[0].Command = []string{"--flag1=value1", "--flag2=value2"}

		kcmDeployment.Spec.Template.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=false"}

		ksDeployment.Spec.Template.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=true"}

		Expect(fakeControlPlaneClient.Create(ctx, kapiDeployment)).To(Succeed())
		Expect(fakeControlPlaneClient.Create(ctx, kcmDeployment)).To(Succeed())
		Expect(fakeControlPlaneClient.Create(ctx, ksDeployment)).To(Succeed())

		node1 := plainNode.DeepCopy()
		node1.ObjectMeta.Name = "node1"

		node2 := plainNode.DeepCopy()
		node2.ObjectMeta.Name = "node2"

		node3 := plainNode.DeepCopy()
		node3.ObjectMeta.Name = "node3"

		Expect(fakeClusterClient.Create(ctx, node1)).To(Succeed())
		Expect(fakeClusterClient.Create(ctx, node2)).To(Succeed())
		Expect(fakeClusterClient.Create(ctx, node3)).To(Succeed())

		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.OwnerReferences[0].UID = "1"
		pod1.Spec.NodeName = "node1"
		pod1.Spec.Containers[0].Command = []string{"--flag1=value1", "--flag2=value2"}

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.OwnerReferences[0].UID = "2"
		pod2.Spec.NodeName = "node1"
		pod2.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=true"}

		pod3 := plainPod.DeepCopy()
		pod3.Name = "pod3"
		pod3.OwnerReferences[0].UID = "3"
		pod3.Spec.NodeName = "node1"
		pod3.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=false"}

		pod4 := plainPod.DeepCopy()
		pod4.Name = "pod4"
		pod4.OwnerReferences[0].UID = "4"
		pod4.Spec.NodeName = "node1"
		pod4.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=true", "--config=/var/lib/config"}

		pod5 := plainPod.DeepCopy()
		pod5.Name = "pod5"
		pod5.OwnerReferences[0].UID = "5"
		pod5.Spec.NodeName = "node1"
		pod5.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=true", "--config=/var/lib/config"}

		pod6 := plainPod.DeepCopy()
		pod6.Name = "pod6"
		pod6.OwnerReferences[0].UID = "6"
		pod6.Spec.NodeName = "node1"
		pod6.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=true", "--config=/var/lib/config"}

		Expect(fakeClusterClient.Create(ctx, pod1)).To(Succeed())
		Expect(fakeClusterClient.Create(ctx, pod2)).To(Succeed())
		Expect(fakeClusterClient.Create(ctx, pod3)).To(Succeed())
		Expect(fakeClusterClient.Create(ctx, pod4)).To(Succeed())
		Expect(fakeClusterClient.Create(ctx, pod5)).To(Succeed())
		Expect(fakeClusterClient.Create(ctx, pod6)).To(Succeed())

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
		r := &v1r11.Rule242400{
			InstanceID:            instanceID,
			ClusterClient:         fakeClusterClient,
			ControlPlaneClient:    fakeControlPlaneClient,
			ControlPlaneNamespace: controlPlaneNamespace,
			ClusterPodContext:     fakePodContext,
			ClusterV1RESTClient:   fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-apiserver", "namespace", "foo")),
			rule.PassedCheckResult("Option featureGates.AllAlpha set to allowed value.", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-controller-manager", "namespace", "foo")),
			rule.FailedCheckResult("Option featureGates.AllAlpha set to not allowed value.", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-scheduler", "namespace", "foo")),
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("cluster", "shoot", "kind", "pod", "name", "pod1", "namespace", "kube-system")),
			rule.FailedCheckResult("Option featureGates.AllAlpha set to not allowed value.", rule.NewTarget("cluster", "shoot", "kind", "pod", "name", "pod2", "namespace", "kube-system")),
			rule.PassedCheckResult("Option featureGates.AllAlpha set to allowed value.", rule.NewTarget("cluster", "shoot", "kind", "pod", "name", "pod3", "namespace", "kube-system")),
			rule.PassedCheckResult("Option featureGates.AllAlpha set to allowed value.", rule.NewTarget("cluster", "shoot", "kind", "pod", "name", "pod4", "namespace", "kube-system")),
			rule.FailedCheckResult("Option featureGates.AllAlpha set to not allowed value.", rule.NewTarget("cluster", "shoot", "kind", "pod", "name", "pod5", "namespace", "kube-system")),
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("cluster", "shoot", "kind", "pod", "name", "pod6", "namespace", "kube-system")),
			rule.PassedCheckResult("Option featureGates.AllAlpha set to allowed value.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node1")),
			rule.FailedCheckResult("Option featureGates.AllAlpha set to not allowed value.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node2")),
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node3")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return correct warning when options are not set properly", func() {
		kapiDeployment.Spec.Template.Spec.Containers[0].Command = []string{"--feature-gates=AllAlpha=false", "--feature-gates=AllAlpha=true"}

		kcmDeployment.Spec.Template.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=not-false"}

		ksDeployment.Spec.Template.Spec.Containers[0].Command = []string{"--feature-gates=AllAlpha=false", "--feature-gates=AllAlpha=true"}

		Expect(fakeControlPlaneClient.Create(ctx, kapiDeployment)).To(Succeed())
		Expect(fakeControlPlaneClient.Create(ctx, kcmDeployment)).To(Succeed())
		Expect(fakeControlPlaneClient.Create(ctx, ksDeployment)).To(Succeed())

		node1 := plainNode.DeepCopy()
		node1.ObjectMeta.Name = "node1"

		Expect(fakeClusterClient.Create(ctx, node1)).To(Succeed())

		pod1 := plainPod.DeepCopy()
		pod1.Name = "pod1"
		pod1.OwnerReferences[0].UID = "1"
		pod1.Spec.NodeName = "node1"
		pod1.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=AllAlpha=true", "--feature-gates=AllAlpha=false"}

		pod2 := plainPod.DeepCopy()
		pod2.Name = "pod2"
		pod2.OwnerReferences[0].UID = "2"
		pod2.Spec.NodeName = "node1"
		pod2.Spec.Containers[0].Command = []string{"--flag1=value1", "--config=/var/lib/config", "--config=/var/lib/config2"}

		Expect(fakeClusterClient.Create(ctx, pod1)).To(Succeed())
		Expect(fakeClusterClient.Create(ctx, pod2)).To(Succeed())

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
		r := &v1r11.Rule242400{
			ClusterClient:         fakeClusterClient,
			ControlPlaneClient:    fakeControlPlaneClient,
			ControlPlaneNamespace: controlPlaneNamespace,
			ClusterPodContext:     fakePodContext,
			ClusterV1RESTClient:   fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.WarningCheckResult("Option featureGates.AllAlpha set more than once in container command.", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-apiserver", "namespace", "foo")),
			rule.WarningCheckResult("Option featureGates.AllAlpha set to neither 'true' nor 'false'.", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-controller-manager", "namespace", "foo")),
			rule.WarningCheckResult("Option featureGates.AllAlpha set more than once in container command.", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-scheduler", "namespace", "foo")),
			rule.WarningCheckResult("Option featureGates.AllAlpha set more than once in container command.", rule.NewTarget("cluster", "shoot", "kind", "pod", "name", "pod1", "namespace", "kube-system")),
			rule.ErroredCheckResult("option config set more than once in container command", rule.NewTarget("cluster", "shoot", "kind", "pod", "name", "pod2", "namespace", "kube-system")),
			rule.PassedCheckResult("Option featureGates.AllAlpha set to allowed value.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node1")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return error when deployments and pods are not found", func() {
		node1 := plainNode.DeepCopy()
		node1.ObjectMeta.Name = "node1"

		Expect(fakeClusterClient.Create(ctx, node1)).To(Succeed())

		fakeRESTClient = &manualfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
			NegotiatedSerializer: scheme.Codecs,
			Client: manualfake.CreateHTTPClient(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(podSecurityNotSetNodeConfig)))}, nil
			}),
		}
		r := &v1r11.Rule242400{
			ClusterClient:         fakeClusterClient,
			ControlPlaneClient:    fakeControlPlaneClient,
			ControlPlaneNamespace: controlPlaneNamespace,
			ClusterV1RESTClient:   fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.ErroredCheckResult("deployments.apps \"kube-apiserver\" not found", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-apiserver", "namespace", "foo")),
			rule.ErroredCheckResult("deployments.apps \"kube-controller-manager\" not found", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-controller-manager", "namespace", "foo")),
			rule.ErroredCheckResult("deployments.apps \"kube-scheduler\" not found", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-scheduler", "namespace", "foo")),
			rule.ErroredCheckResult("kube-proxy pods not found", rule.NewTarget("cluster", "shoot", "selector", "role=proxy")),
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node1")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return skipped check result when kubeProxyDiabled option is set to true", func() {
		node1 := plainNode.DeepCopy()
		node1.ObjectMeta.Name = "node1"

		Expect(fakeClusterClient.Create(ctx, node1)).To(Succeed())

		fakeRESTClient = &manualfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
			NegotiatedSerializer: scheme.Codecs,
			Client: manualfake.CreateHTTPClient(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(podSecurityNotSetNodeConfig)))}, nil
			}),
		}
		r := &v1r11.Rule242400{
			ClusterClient:         fakeClusterClient,
			ControlPlaneClient:    fakeControlPlaneClient,
			ControlPlaneNamespace: controlPlaneNamespace,
			ClusterV1RESTClient:   fakeRESTClient,
			Options: &option.KubeProxyOptions{
				KubeProxyDisabled: true,
			},
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.ErroredCheckResult("deployments.apps \"kube-apiserver\" not found", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-apiserver", "namespace", "foo")),
			rule.ErroredCheckResult("deployments.apps \"kube-controller-manager\" not found", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-controller-manager", "namespace", "foo")),
			rule.ErroredCheckResult("deployments.apps \"kube-scheduler\" not found", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-scheduler", "namespace", "foo")),
			rule.AcceptedCheckResult("Kube-proxy is disabled for cluster.", rule.NewTarget()),
			rule.PassedCheckResult("Option featureGates.AllAlpha not set.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node1")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return warning when nodes are not found", func() {
		fakeRESTClient = &manualfake.RESTClient{}
		r := &v1r11.Rule242400{
			ClusterClient:         fakeClusterClient,
			ControlPlaneClient:    fakeControlPlaneClient,
			ControlPlaneNamespace: controlPlaneNamespace,
			ClusterV1RESTClient:   fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.ErroredCheckResult("deployments.apps \"kube-apiserver\" not found", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-apiserver", "namespace", "foo")),
			rule.ErroredCheckResult("deployments.apps \"kube-controller-manager\" not found", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-controller-manager", "namespace", "foo")),
			rule.ErroredCheckResult("deployments.apps \"kube-scheduler\" not found", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-scheduler", "namespace", "foo")),
			rule.WarningCheckResult("No nodes found.", rule.NewTarget("cluster", "shoot")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})
})
