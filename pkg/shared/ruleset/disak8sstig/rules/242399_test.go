// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/Masterminds/semver/v3"
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

var _ = Describe("#242399", func() {
	const (
		dynamicKubeletConfigAllowedNodeConfig    = `{"kubeletconfig":{"featureGates":{"DynamicKubeletConfig":false}}}`
		dynamicKubeletConfigNotAllowedNodeConfig = `{"kubeletconfig":{"featureGates":{"DynamicKubeletConfig":true}}}`
		dynamicKubeletConfigNotSetNodeConfig     = `{"kubeletconfig":{"authentication":{"webhook":{"enabled":true,"cacheTTL":"2m0s"}}}}`
	)

	var (
		fakeClient           client.Client
		fakeRESTClient       rest.Interface
		plainNode            *corev1.Node
		kubernetesVersion125 *semver.Version
		kubernetesVersion126 *semver.Version
		ctx                  = context.TODO()
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

		kubernetesVersion125 = semver.MustParse("1.25.0")
		kubernetesVersion126 = semver.MustParse("1.26.0")
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

		fakeRESTClient = &manualfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
			NegotiatedSerializer: scheme.Codecs,
			Client: manualfake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
				switch req.URL.String() {
				case "https://localhost/nodes/node1/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(dynamicKubeletConfigAllowedNodeConfig)))}, nil
				case "https://localhost/nodes/node2/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(dynamicKubeletConfigNotAllowedNodeConfig)))}, nil
				case "https://localhost/nodes/node3/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(dynamicKubeletConfigNotSetNodeConfig)))}, nil
				default:
					return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(&bytes.Buffer{})}, nil
				}
			}),
		}
		r := &rules.Rule242399{
			Client:            fakeClient,
			KubernetesVersion: kubernetesVersion125,
			V1RESTClient:      fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("Option featureGates.DynamicKubeletConfig set to allowed value.", rule.NewTarget("kind", "node", "name", "node1")),
			rule.FailedCheckResult("Option featureGates.DynamicKubeletConfig set to not allowed value.", rule.NewTarget("kind", "node", "name", "node2")),
			rule.PassedCheckResult("Option featureGates.DynamicKubeletConfig not set.", rule.NewTarget("kind", "node", "name", "node3")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should skip rule when kubernetes version is > 1.25", func() {
		fakeRESTClient = &manualfake.RESTClient{}
		r := &rules.Rule242399{
			Client:            fakeClient,
			KubernetesVersion: kubernetesVersion126,
			V1RESTClient:      fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.SkippedCheckResult("Option featureGates.DynamicKubeletConfig removed in Kubernetes v1.26.", rule.NewTarget("details", "Used Kubernetes version 1.26.0.")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return warn when nodes are not found", func() {
		fakeRESTClient = &manualfake.RESTClient{}
		r := &rules.Rule242399{
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
