// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	kubernetesgardener "github.com/gardener/gardener/pkg/client/kubernetes"
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

	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242392", func() {
	const (
		authorizationModeAllowedConfig = `authorization:
  mode: Webhook
`
		authorizationModeNotAllowedConfig = `authorization:
  mode: AlwaysAllow
`
		authorizationModeNotSetConfig = `maxPods: 100
`
		authorizationModeAllowedNodeConfig    = `{"kubeletconfig":{"authorization":{"mode":"Webhook"}}}`
		authorizationModeNotAllowedNodeConfig = `{"kubeletconfig":{"authorization":{"mode":"AlwaysAllow"}}}`
		authorizationModeNotSetNodeConfig     = `{"kubeletconfig":{"authentication":{"webhook":{"enabled":true,"cacheTTL":"2m0s"}}}}`
	)

	var (
		fakeControlPlaneClient client.Client
		fakeClusterClient      client.Client
		fakeClusterRESTClient  rest.Interface
		fakeClusterPodContext  pod.PodContext
		ctx                    = context.TODO()
		workers                *extensionsv1alpha1.Worker
		namespace              = "foo"
	)

	BeforeEach(func() {
		v1r11.Generator = &FakeRandString{CurrentChar: 'a'}
		fakeControlPlaneClient = fakeclient.NewClientBuilder().WithScheme(kubernetesgardener.SeedScheme).Build()
		fakeClusterClient = fakeclient.NewClientBuilder().WithScheme(kubernetesgardener.ShootScheme).Build()

		workers = &extensionsv1alpha1.Worker{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "worker1",
				Namespace: namespace,
			},
			Spec: extensionsv1alpha1.WorkerSpec{
				Pools: []extensionsv1alpha1.WorkerPool{
					{
						Name: "pool1",
					},
					{
						Name: "pool2",
					},
					{
						Name: "pool3",
					},
					{
						Name: "pool4",
					},
				},
			},
		}
		Expect(fakeControlPlaneClient.Create(ctx, workers)).To(Succeed())

		plainAllocatableNode := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{},
			},
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

		node1 := plainAllocatableNode.DeepCopy()
		node1.ObjectMeta.Name = "node1"
		node1.ObjectMeta.Labels["worker.gardener.cloud/pool"] = "pool1"
		Expect(fakeClusterClient.Create(ctx, node1)).To(Succeed())

		node2 := plainAllocatableNode.DeepCopy()
		node2.ObjectMeta.Name = "node2"
		node2.ObjectMeta.Labels["worker.gardener.cloud/pool"] = "pool2"
		Expect(fakeClusterClient.Create(ctx, node2)).To(Succeed())

		node3 := plainAllocatableNode.DeepCopy()
		node3.ObjectMeta.Name = "node3"
		node3.ObjectMeta.Labels["worker.gardener.cloud/pool"] = "pool3"
		node3.Status.Conditions[0].Type = corev1.NodeReady
		node3.Status.Conditions[0].Status = corev1.ConditionFalse
		Expect(fakeClusterClient.Create(ctx, node3)).To(Succeed())

		node4 := plainAllocatableNode.DeepCopy()
		node4.ObjectMeta.Name = "node4"
		node4.ObjectMeta.Labels["worker.gardener.cloud/pool"] = "pool2"
		Expect(fakeClusterClient.Create(ctx, node4)).To(Succeed())

		node5 := plainAllocatableNode.DeepCopy()
		node5.ObjectMeta.Name = "node5"
		node5.ObjectMeta.Labels["worker.gardener.cloud/pool"] = "pool4"
		node5.Status.Allocatable["pods"] = resource.MustParse("0.0")
		Expect(fakeClusterClient.Create(ctx, node5)).To(Succeed())

		fakeClusterRESTClient = &manualfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
			NegotiatedSerializer: scheme.Codecs,
			Client: manualfake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
				switch req.URL.String() {
				case "https://localhost/nodes/node1/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(authorizationModeAllowedNodeConfig)))}, nil
				case "https://localhost/nodes/node2/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(authorizationModeNotAllowedNodeConfig)))}, nil
				case "https://localhost/nodes/node4/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(authorizationModeNotSetNodeConfig)))}, nil
				case "https://localhost/nodes/node5/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(authorizationModeAllowedNodeConfig)))}, nil
				default:
					return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(&bytes.Buffer{})}, nil
				}
			}),
		}
	})

	DescribeTable("Run cases",
		func(executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			alwaysExpectedCheckResults := []rule.CheckResult{
				rule.PassedCheckResult("Option authorization.mode set to allowed value.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node1")),
				rule.FailedCheckResult("Option authorization.mode set to not allowed value.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node2", "details", "Authorization Mode set to AlwaysAllow")),
				rule.WarningCheckResult("Node is not in Ready state.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node3")),
				rule.FailedCheckResult("Option authorization.mode not set.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node4")),
				rule.PassedCheckResult("Option authorization.mode set to allowed value.", rule.NewTarget("cluster", "shoot", "kind", "node", "name", "node5")),
			}
			expectedCheckResults = append(expectedCheckResults, alwaysExpectedCheckResults...)
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &v1r11.Rule242392{
				Logger:                  testLogger,
				ControlPlaneClient:      fakeControlPlaneClient,
				ControlPlaneNamespace:   namespace,
				ClusterClient:           fakeClusterClient,
				ClusterCoreV1RESTClient: fakeClusterRESTClient,
				ClusterPodContext:       fakeClusterPodContext,
			}

			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should return correct checkResults when one node's /healthz enpoint can be reached, another has authorization-mode kubelet flag set",
			[][]string{{"healthy"}, {"Unauthorized", "--authorization-mode=AlwaysAllow"}},
			[][]error{{nil}, {nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("Kubelet always allows access (or could not be probed).", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool1")),
				rule.FailedCheckResult("Use of deprecated kubelet config flag authorization-mode.", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool2")),
				rule.WarningCheckResult("There are no ready nodes with at least 1 allocatable spot for worker group.", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool3")),
				rule.WarningCheckResult("There are no ready nodes with at least 1 allocatable spot for worker group.", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool4")),
			}),
		Entry("should return correct checkResults when nodes have authorization.mode set",
			[][]string{{"Unauthorized", "--not-authorization-mode=Webhook --config=./config", authorizationModeAllowedConfig}, {"Unauthorized", "--not-authorization-mode=Webhook --config=./config", authorizationModeNotAllowedConfig}},
			[][]error{{nil, nil, nil}, {nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("Option authorization.mode set to allowed value.", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool1")),
				rule.FailedCheckResult("Option authorization.mode set to not allowed value.", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool2", "details", "Authorization Mode set to AlwaysAllow")),
				rule.WarningCheckResult("There are no ready nodes with at least 1 allocatable spot for worker group.", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool3")),
				rule.WarningCheckResult("There are no ready nodes with at least 1 allocatable spot for worker group.", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool4")),
			}),
		Entry("should return correct checkResults when nodes do not have authorization.mode set",
			[][]string{{"Unauthorized", "--not-authorization-mode=Webhook --config=./config", authorizationModeNotSetConfig}, {"Unauthorized", "--not-authorization-mode=Webhook, --config=./config", authorizationModeNotSetConfig}},
			[][]error{{nil, nil, nil}, {nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("Option authorization.mode not set.", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool1")),
				rule.FailedCheckResult("Option authorization.mode not set.", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool2")),
				rule.WarningCheckResult("There are no ready nodes with at least 1 allocatable spot for worker group.", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool3")),
				rule.WarningCheckResult("There are no ready nodes with at least 1 allocatable spot for worker group.", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool4")),
			}),
		Entry("should return correct checkResults when execute errors",
			[][]string{{""}, {"Unauthorized", ""}},
			[][]error{{fmt.Errorf("command stderr output: sh: 1: -c: not found")}, {nil, fmt.Errorf("command stderr output: sh: 1: netstat: not found")}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("command stderr output: sh: 1: -c: not found", rule.NewTarget("cluster", "shoot", "kind", "pod", "namespace", "kube-system", "name", "diki-node-files-aaaaaaaaaa")),
				rule.ErroredCheckResult("command stderr output: sh: 1: netstat: not found", rule.NewTarget("cluster", "shoot", "kind", "pod", "namespace", "kube-system", "name", "diki-node-files-bbbbbbbbbb")),
				rule.WarningCheckResult("There are no ready nodes with at least 1 allocatable spot for worker group.", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool3")),
				rule.WarningCheckResult("There are no ready nodes with at least 1 allocatable spot for worker group.", rule.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool4")),
			}),
	)
})
