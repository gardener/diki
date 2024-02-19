// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11_test

import (
	"bytes"
	"context"
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
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ = Describe("#242397", func() {
	const (
		staticPodPathEmptyNodeConfig  = `{"kubeletconfig":{"staticPodPath":" "}}`
		staticPodPathSetNodeConfig    = `{"kubeletconfig":{"staticPodPath":"/foo/bar"}}`
		staticPodPathNotSetNodeConfig = `{"kubeletconfig":{"authentication":{"webhook":{"enabled":true,"cacheTTL":"2m0s"}}}}`
	)

	var (
		fakeClient     client.Client
		fakeRESTClient rest.Interface
		plainNode      *corev1.Node
		ctx            = context.TODO()
	)

	BeforeEach(func() {
		v1r11.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
		fakeClient = fakeclient.NewClientBuilder().Build()

		plainNode = &corev1.Node{
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
					"pods": resource.MustParse("0.0"),
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

		fakeRESTClient = &manualfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
			NegotiatedSerializer: scheme.Codecs,
			Client: manualfake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
				switch req.URL.String() {
				case "https://localhost/nodes/node1/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(staticPodPathEmptyNodeConfig)))}, nil
				case "https://localhost/nodes/node2/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(staticPodPathSetNodeConfig)))}, nil
				case "https://localhost/nodes/node3/proxy/configz":
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(staticPodPathNotSetNodeConfig)))}, nil
				default:
					return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(&bytes.Buffer{})}, nil
				}
			}),
		}
		r := &v1r11.Rule242397{
			Logger:       testLogger,
			Client:       fakeClient,
			V1RESTClient: fakeRESTClient,
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.FailedCheckResult("Option staticPodPath set.", rule.NewTarget("kind", "node", "name", "node1")),
			rule.FailedCheckResult("Option staticPodPath set.", rule.NewTarget("kind", "node", "name", "node2")),
			rule.PassedCheckResult("Option staticPodPath not set.", rule.NewTarget("kind", "node", "name", "node3")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})

	It("should return correct checkResults only for selected nodes", func() {
		node1 := plainNode.DeepCopy()
		node1.ObjectMeta.Name = "node1"
		node1.ObjectMeta.Labels["foo"] = "bar1"
		Expect(fakeClient.Create(ctx, node1)).To(Succeed())

		node2 := plainNode.DeepCopy()
		node2.ObjectMeta.Name = "node2"
		node2.ObjectMeta.Labels["foo"] = "bar2"
		Expect(fakeClient.Create(ctx, node2)).To(Succeed())

		node3 := plainNode.DeepCopy()
		node3.ObjectMeta.Name = "node3"
		node3.ObjectMeta.Labels["foo"] = "bar1"
		Expect(fakeClient.Create(ctx, node3)).To(Succeed())

		fakeRESTClient = &manualfake.RESTClient{
			GroupVersion:         schema.GroupVersion{Group: "", Version: "v1"},
			NegotiatedSerializer: scheme.Codecs,
			Client: manualfake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(staticPodPathNotSetNodeConfig)))}, nil
			}),
		}
		r := &v1r11.Rule242397{
			Logger:       testLogger,
			Client:       fakeClient,
			V1RESTClient: fakeRESTClient,
			Options: &v1r11.Options242397{
				GroupByLabels: []string{"foo"},
			},
		}
		ruleResult, err := r.Run(ctx)

		expectedCheckResults := []rule.CheckResult{
			rule.PassedCheckResult("Option staticPodPath not set.", rule.NewTarget("kind", "node", "name", "node1")),
			rule.PassedCheckResult("Option staticPodPath not set.", rule.NewTarget("kind", "node", "name", "node2")),
		}

		Expect(err).To(BeNil())
		Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
	})
})
