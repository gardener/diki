// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10_test

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	manualfake "k8s.io/client-go/rest/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r10"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242420", func() {
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
		v1r10.Generator = &FakeRandString{CurrentChar: 'a'}
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
				},
			},
		}

		Expect(fakeControlPlaneClient.Create(ctx, workers)).To(Succeed())

		node1 := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node1",
				Labels: map[string]string{
					"worker.gardener.cloud/pool": "pool1",
				},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{
						Type:   corev1.NodeReady,
						Status: corev1.ConditionTrue,
					},
				},
			},
		}
		Expect(fakeClusterClient.Create(ctx, node1)).To(Succeed())

		node2 := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node2",
				Labels: map[string]string{
					"worker.gardener.cloud/pool": "pool2",
				},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{
						Type:   corev1.NodeReady,
						Status: corev1.ConditionTrue,
					},
				},
			},
		}
		Expect(fakeClusterClient.Create(ctx, node2)).To(Succeed())

		node3 := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node3",
				Labels: map[string]string{
					"worker.gardener.cloud/pool": "pool3",
				},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{
						Type:   corev1.NodeReady,
						Status: corev1.ConditionFalse,
					},
				},
			},
		}
		Expect(fakeClusterClient.Create(ctx, node3)).To(Succeed())

		node4 := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node4",
				Labels: map[string]string{
					"worker.gardener.cloud/pool": "pool2",
				},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{
						Type:   corev1.NodeReady,
						Status: corev1.ConditionTrue,
					},
				},
			},
		}
		Expect(fakeClusterClient.Create(ctx, node4)).To(Succeed())

		fakeClusterRESTClient = &manualfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
			NegotiatedSerializer: scheme.Codecs,
			Client: manualfake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
				switch req.URL.String() {
				case "https://localhost/nodes/node1/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(clientCaFileEmptyNodeConfig)))}, nil
				case "https://localhost/nodes/node2/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(clientCaFileSetNodeConfig)))}, nil
				case "https://localhost/nodes/node4/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(clientCaFileNotSetNodeConfig)))}, nil
				default:
					return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(&bytes.Buffer{})}, nil
				}
			}),
		}
	})

	DescribeTable("Run cases",
		func(executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			alwaysExpectedCheckResults := []rule.CheckResult{
				rule.FailedCheckResult("Option authentication.x509.clientCAFile is empty.", gardener.NewTarget("cluster", "shoot", "kind", "node", "name", "node1")),
				rule.PassedCheckResult("Option authentication.x509.clientCAFile set.", gardener.NewTarget("cluster", "shoot", "kind", "node", "name", "node2")),
				rule.WarningCheckResult("Node is not in Ready state.", gardener.NewTarget("cluster", "shoot", "kind", "node", "name", "node3")),
				rule.FailedCheckResult("Option authentication.x509.clientCAFile not set.", gardener.NewTarget("cluster", "shoot", "kind", "node", "name", "node4")),
			}
			expectedCheckResults = append(expectedCheckResults, alwaysExpectedCheckResults...)
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &v1r10.Rule242420{
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

		Entry("should return correct checkResults when execute errors, and one node has pod-manifest-path kubelet flag set",
			[][]string{{""}, {"--client-ca-file=/foo/bar"}},
			[][]error{{fmt.Errorf("command stderr output: sh: 1: -c: not found")}, {nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("command stderr output: sh: 1: -c: not found", gardener.NewTarget("cluster", "shoot", "kind", "pod", "namespace", "kube-system", "name", "diki-node-files-aaaaaaaaaa")),
				rule.FailedCheckResult("Use of deprecated kubelet config flag client-ca-file.", gardener.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool2")),
				rule.WarningCheckResult("There are no nodes in Ready state for worker group.", gardener.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool3")),
			}),
		Entry("should return correct checkResults when nodes have authentication.x509.clientCAFile set",
			[][]string{{"--not-client-ca-file=/foo/bar --config=./config", clientCaFileEmptyConfig}, {"--not-client-ca-file=/foo/bar --config=./config", clientCaFileSetConfig}},
			[][]error{{nil, nil}, {nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("Option authentication.x509.clientCAFile is empty.", gardener.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool1")),
				rule.PassedCheckResult("Option authentication.x509.clientCAFile set.", gardener.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool2")),
				rule.WarningCheckResult("There are no nodes in Ready state for worker group.", gardener.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool3")),
			}),
		Entry("should return correct checkResults when nodes do not have authentication.x509.clientCAFile set",
			[][]string{{"--not-client-ca-file=/foo/bar --config=./config", clientCaFileNotSetConfig}, {"--not-client-ca-file=/foo/bar, --config=./config", clientCaFileNotSetConfig}},
			[][]error{{nil, nil}, {nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("Option authentication.x509.clientCAFile not set.", gardener.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool1")),
				rule.FailedCheckResult("Option authentication.x509.clientCAFile not set.", gardener.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool2")),
				rule.WarningCheckResult("There are no nodes in Ready state for worker group.", gardener.NewTarget("cluster", "seed", "kind", "workerGroup", "name", "pool3")),
			}),
	)
})

const (
	clientCaFileEmptyConfig = `authentication:
  x509:
    clientCAFile: ""
`
	clientCaFileSetConfig = `authentication:
  x509:
    clientCAFile: /foo/bar
`
	clientCaFileNotSetConfig = `maxPods: 100
`
	clientCaFileEmptyNodeConfig  = `{"kubeletconfig":{"authentication":{"x509":{"clientCAFile":""}}}}`
	clientCaFileSetNodeConfig    = `{"kubeletconfig":{"authentication":{"x509":{"clientCAFile":"/foo/bar"}}}}`
	clientCaFileNotSetNodeConfig = `{"kubeletconfig":{"authentication":{"webhook":{"enabled":true,"cacheTTL":"2m0s"}}}}`
)
