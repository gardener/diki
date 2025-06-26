// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	fakestrgen "github.com/gardener/diki/pkg/internal/stringgen/fake"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#242404", func() {
	var (
		kubeletPID = "1"
		instanceID = "1"
		fakeClient client.Client
		podContext pod.PodContext
		ctx        = context.TODO()
		plainNode  *corev1.Node
		node1      *corev1.Node
		node2      *corev1.Node
	)

	BeforeEach(func() {
		rules.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
		fakeClient = fakeclient.NewClientBuilder().Build()

		plainNode = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "foo",
				Labels: map[string]string{},
			},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{
					"pods": resource.MustParse("100.0"),
				},
			},
		}

		node1 = plainNode.DeepCopy()
		node1.Name = "node1"
		node1.Labels["foo"] = "bar"

		node2 = plainNode.DeepCopy()
		node2.Name = "node2"
		node2.Labels["foo"] = "bar"

	})

	It("should error when no allocatable nodes are found", func() {
		r := rules.Rule242404{
			Client: fakeClient,
		}

		res, err := r.Run(ctx)
		Expect(err).To(BeNil())

		Expect(res.CheckResults).To(Equal([]rule.CheckResult{
			{Status: rule.Errored, Message: "no allocatable nodes could be selected", Target: rule.NewTarget()},
		}))

	})

	DescribeTable("Run cases",
		func(options rules.Options242404, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			Expect(fakeClient.Create(ctx, node1)).To(Succeed())
			Expect(fakeClient.Create(ctx, node2)).To(Succeed())

			podContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &rules.Rule242404{
				Logger:     testLogger,
				InstanceID: instanceID,
				Client:     fakeClient,
				PodContext: podContext,
				Options:    &options,
			}

			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())

			Expect(ruleResult.CheckResults).To(ConsistOf(expectedCheckResults))
		},

		Entry("should return correct checkResults", nil,
			[][]string{{kubeletPID, "--hostname-override=/foo/bar --config=./config"}, {kubeletPID, "--not-hostname-override --config=./config"}},
			[][]error{{nil, nil}, {nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("Flag hostname-override set.", rule.NewTarget("kind", "Node", "name", "node1")),
				rule.PassedCheckResult("Flag hostname-override not set.", rule.NewTarget("kind", "Node", "name", "node2")),
			}),
		Entry("should return correct checkResults only for selected nodes",
			rules.Options242404{
				NodeGroupByLabels: []string{"foo"},
			},
			[][]string{{kubeletPID, "--hostname-override=/foo/bar --config=./config"}},
			[][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("Flag hostname-override set.", rule.NewTarget("kind", "Node", "name", "node1")),
			}),
		Entry("should return correct checkResults when commands error", nil,
			[][]string{{""}, {kubeletPID, "--hostname-override=/foo/bar --config=./config"}},
			[][]error{{errors.New("foo")}, {nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242404-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
				rule.FailedCheckResult("Flag hostname-override set.", rule.NewTarget("kind", "Node", "name", "node2")),
			}),
	)
})
