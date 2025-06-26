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

var _ = Describe("#242393", func() {
	var (
		instanceID = "1"
		fakeClient client.Client
		podContext pod.PodContext
		ctx        = context.TODO()
		plainNode  *corev1.Node
		node1      *corev1.Node
		node2      *corev1.Node
		node3      *corev1.Node
		node4      *corev1.Node
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
		node1.Labels["foo"] = "foo"

		node2 = plainNode.DeepCopy()
		node2.Name = "node2"
		node2.Labels["foo"] = "foo"

		node3 = plainNode.DeepCopy()
		node3.Name = "node3"
		node3.Labels["foo"] = "bar"

		node4 = plainNode.DeepCopy()
		node4.Name = "node4"

		Expect(fakeClient.Create(ctx, node1)).To(Succeed())
		Expect(fakeClient.Create(ctx, node2)).To(Succeed())
		Expect(fakeClient.Create(ctx, node3)).To(Succeed())
		Expect(fakeClient.Create(ctx, node4)).To(Succeed())
	})

	DescribeTable("Run cases",
		func(options rules.Options242393, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			podContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &rules.Rule242393{
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
			[][]string{{"", "foo"}, {"", "Inactive"},
				{"", "Active"}, {"port used!"}},
			[][]error{{nil, nil}, {nil, nil}, {nil, nil}, {nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("SSH daemon inactive (or could not be probed)", rule.NewTarget("kind", "Node", "name", "node1")),
				rule.PassedCheckResult("SSH daemon service not installed", rule.NewTarget("kind", "Node", "name", "node2")),
				rule.FailedCheckResult("SSH daemon active", rule.NewTarget("kind", "Node", "name", "node3")),
				rule.FailedCheckResult("SSH daemon started on port 22", rule.NewTarget("kind", "Node", "name", "node4")),
			}),
		Entry("should return correct checkResults only for selected nodes",
			rules.Options242393{
				NodeGroupByLabels: []string{"foo"},
			},
			[][]string{{"", "foo"}, {"", "foo"}},
			[][]error{{nil, nil}, {nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("SSH daemon inactive (or could not be probed)", rule.NewTarget("kind", "Node", "name", "node1")),
				rule.PassedCheckResult("SSH daemon inactive (or could not be probed)", rule.NewTarget("kind", "Node", "name", "node3")),
				rule.WarningCheckResult("Node is missing a label", rule.NewTarget("kind", "Node", "name", "node4", "label", "foo")),
			}),
		Entry("should return correct checkResults when commands error", nil,
			[][]string{{""}, {"", "foo"},
				{"", "foo"}, {"", "foo"}},
			[][]error{{errors.New("foo")}, {nil, errors.New("bar")}, {nil, nil}, {nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242393-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242393-bbbbbbbbbb", "namespace", "kube-system", "kind", "Pod")),
				rule.PassedCheckResult("SSH daemon inactive (or could not be probed)", rule.NewTarget("kind", "Node", "name", "node3")),
				rule.PassedCheckResult("SSH daemon inactive (or could not be probed)", rule.NewTarget("kind", "Node", "name", "node4")),
			}),
	)
})
