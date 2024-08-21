// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"bytes"
	"context"
	"io"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	manualfake "k8s.io/client-go/rest/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	fakestrgen "github.com/gardener/diki/pkg/internal/stringgen/fake"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#242425", func() {
	const (
		tlsCertFileSetNodeConfig        = `{"kubeletconfig":{"tlsCertFile":"/foo/bar"}}`
		tlsCertFileEmptyNodeConfig      = `{"kubeletconfig":{"tlsCertFile":""}}`
		serverTLSBootstrapSetNodeConfig = `{"kubeletconfig":{"serverTLSBootstrap":true,"tlsCertFile":"/foo/bar"}}`
		tlsCertFileNotSetNodeConfig     = `{"kubeletconfig":{"authentication":{"webhook":{"enabled":true,"cacheTTL":"2m0s"}}}}`
	)

	var (
		fakeClient     client.Client
		fakeRESTClient rest.Interface
		plainNode      *corev1.Node
		ctx            = context.TODO()
	)

	BeforeEach(func() {
		rules.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
		fakeClient = fakeclient.NewClientBuilder().Build()

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

		node4 := plainNode.DeepCopy()
		node4.ObjectMeta.Name = "node4"
		Expect(fakeClient.Create(ctx, node4)).To(Succeed())

		fakeRESTClient = &manualfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
			NegotiatedSerializer: scheme.Codecs,
			Client: manualfake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
				switch req.URL.String() {
				case "https://localhost/nodes/node1/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(tlsCertFileSetNodeConfig)))}, nil
				case "https://localhost/nodes/node2/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(tlsCertFileEmptyNodeConfig)))}, nil
				case "https://localhost/nodes/node3/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(serverTLSBootstrapSetNodeConfig)))}, nil
				case "https://localhost/nodes/node4/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(tlsCertFileNotSetNodeConfig)))}, nil
				default:
					return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(&bytes.Buffer{})}, nil
				}
			}),
		}
		r := &rules.Rule242425{
			Client:       fakeClient,
			V1RESTClient: fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("Option tlsCertFile set.", rule.NewTarget("kind", "node", "name", "node1")),
			rule.FailedCheckResult("Option tlsCertFile is empty.", rule.NewTarget("kind", "node", "name", "node2")),
			rule.PassedCheckResult("Kubelet rotates server certificates automatically itself.", rule.NewTarget("kind", "node", "name", "node3")),
			rule.FailedCheckResult("Option tlsCertFile not set.", rule.NewTarget("kind", "node", "name", "node4")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return warn when nodes are not found", func() {
		fakeRESTClient = &manualfake.RESTClient{}
		r := &rules.Rule242425{
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
