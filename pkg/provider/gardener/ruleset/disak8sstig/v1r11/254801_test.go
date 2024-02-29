// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11_test

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/Masterminds/semver/v3"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	manualfake "k8s.io/client-go/rest/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	fakestrgen "github.com/gardener/diki/pkg/internal/stringgen/fake"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ = Describe("#254801", func() {
	const (
		podSecurityAllowedNodeConfig    = `{"kubeletconfig":{"featureGates":{"PodSecurity":true}}}`
		podSecurityNotAllowedNodeConfig = `{"kubeletconfig":{"featureGates":{"PodSecurity":false}}}`
		podSecurityNotSetNodeConfig     = `{"kubeletconfig":{"authentication":{"webhook":{"enabled":true,"cacheTTL":"2m0s"}}}}`
		controlPlaneNamespace           = "foo"
	)

	var (
		fakeControlPlaneClient client.Client
		fakeClusterClient      client.Client
		fakeRESTClient         rest.Interface
		plainNode              *corev1.Node
		plainDeployment        *appsv1.Deployment
		kapiDeployment         *appsv1.Deployment
		kcmDeployment          *appsv1.Deployment
		ksDeployment           *appsv1.Deployment
		kubernetesVersion127   *semver.Version
		kubernetesVersion128   *semver.Version
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

		kubernetesVersion127 = semver.MustParse("1.27.0")
		kubernetesVersion128 = semver.MustParse("1.28.0")
	})

	It("should return correct checkResults", func() {
		kapiDeployment.Spec.Template.Spec.Containers[0].Command = []string{"--flag1=value1", "--flag2=value2"}

		kcmDeployment.Spec.Template.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=PodSecurity=true"}

		ksDeployment.Spec.Template.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=PodSecurity=false"}

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
		r := &v1r11.Rule254801{
			ClusterClient:         fakeClusterClient,
			ControlPlaneClient:    fakeControlPlaneClient,
			ControlPlaneNamespace: controlPlaneNamespace,
			ClusterVersion:        kubernetesVersion127,
			ClusterV1RESTClient:   fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("Option featureGates.PodSecurity not set.", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-apiserver", "namespace", "foo")),
			rule.PassedCheckResult("Option featureGates.PodSecurity set to allowed value.", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-controller-manager", "namespace", "foo")),
			rule.FailedCheckResult("Option featureGates.PodSecurity set to not allowed value.", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-scheduler", "namespace", "foo")),
			rule.PassedCheckResult("Option featureGates.PodSecurity set to allowed value.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node1")),
			rule.FailedCheckResult("Option featureGates.PodSecurity set to not allowed value.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node2")),
			rule.PassedCheckResult("Option featureGates.PodSecurity not set.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node3")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return correct warning when options are not set properly", func() {
		kapiDeployment.Spec.Template.Spec.Containers[0].Command = []string{"--feature-gates=PodSecurity=false", "--feature-gates=PodSecurity=true"}

		kcmDeployment.Spec.Template.Spec.Containers[0].Command = []string{"--flag1=value1", "--feature-gates=PodSecurity=not-false"}

		ksDeployment.Spec.Template.Spec.Containers[0].Command = []string{"--feature-gates=PodSecurity=false", "--feature-gates=PodSecurity=true"}

		Expect(fakeControlPlaneClient.Create(ctx, kapiDeployment)).To(Succeed())
		Expect(fakeControlPlaneClient.Create(ctx, kcmDeployment)).To(Succeed())
		Expect(fakeControlPlaneClient.Create(ctx, ksDeployment)).To(Succeed())

		node1 := plainNode.DeepCopy()
		node1.ObjectMeta.Name = "node1"

		Expect(fakeClusterClient.Create(ctx, node1)).To(Succeed())

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
		r := &v1r11.Rule254801{
			ClusterClient:         fakeClusterClient,
			ControlPlaneClient:    fakeControlPlaneClient,
			ControlPlaneNamespace: controlPlaneNamespace,
			ClusterVersion:        kubernetesVersion127,
			ClusterV1RESTClient:   fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.WarningCheckResult("Option featureGates.PodSecurity has been set more than once in container command.", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-apiserver", "namespace", "foo")),
			rule.WarningCheckResult("Option featureGates.PodSecurity set to neither 'true' nor 'false'.", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-controller-manager", "namespace", "foo")),
			rule.WarningCheckResult("Option featureGates.PodSecurity has been set more than once in container command.", rule.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-scheduler", "namespace", "foo")),
			rule.PassedCheckResult("Option featureGates.PodSecurity set to allowed value.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node1")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should skip rule when kubernetes version is > 1.25", func() {
		fakeRESTClient = &manualfake.RESTClient{}
		r := &v1r11.Rule254801{
			ClusterClient:         fakeClusterClient,
			ControlPlaneClient:    fakeControlPlaneClient,
			ControlPlaneNamespace: controlPlaneNamespace,
			ControlPlaneVersion:   kubernetesVersion128,
			ClusterVersion:        kubernetesVersion128,
			ClusterV1RESTClient:   fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.SkippedCheckResult("Option featureGates.PodSecurity removed in Kubernetes v1.28.", rule.NewTarget("cluster", "seed", "details", "Used Kubernetes version 1.28.0.")),
			rule.SkippedCheckResult("Option featureGates.PodSecurity removed in Kubernetes v1.28.", rule.NewTarget("cluster", "shoot", "details", "Used Kubernetes version 1.28.0.")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return warn when nodes are not found and error if deployments are not found", func() {
		fakeRESTClient = &manualfake.RESTClient{}
		r := &v1r11.Rule254801{
			ClusterClient:         fakeClusterClient,
			ControlPlaneClient:    fakeControlPlaneClient,
			ControlPlaneNamespace: controlPlaneNamespace,
			ClusterV1RESTClient:   fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.ErroredCheckResult("deployments.apps \"kube-apiserver\" not found", rule.NewTarget("cluster", "seed")),
			rule.ErroredCheckResult("deployments.apps \"kube-controller-manager\" not found", rule.NewTarget("cluster", "seed")),
			rule.ErroredCheckResult("deployments.apps \"kube-scheduler\" not found", rule.NewTarget("cluster", "seed")),
			rule.WarningCheckResult("No nodes found.", rule.NewTarget("cluster", "shoot")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})
})
