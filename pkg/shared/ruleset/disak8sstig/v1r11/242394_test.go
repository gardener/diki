// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11_test

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
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ = Describe("#242394", func() {
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
		v1r11.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
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
		func(options v1r11.Options242394, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			podContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &v1r11.Rule242394{
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
			[][]string{{"", "foo"}, {"", ""},
				{"", "Alias"}, {"port used!"}},
			[][]error{{nil, nil}, {nil, errors.New(" foo NO such file or directory  ")}, {nil, nil}, {nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("SSH daemon disabled (or could not be probed)", rule.NewTarget("kind", "node", "name", "node1")),
				rule.PassedCheckResult("SSH daemon service not installed", rule.NewTarget("kind", "node", "name", "node2")),
				rule.FailedCheckResult("SSH daemon enabled", rule.NewTarget("kind", "node", "name", "node3")),
				rule.FailedCheckResult("SSH daemon started on port 22", rule.NewTarget("kind", "node", "name", "node4")),
			}),
		Entry("should return correct checkResults only for selected nodes",
			v1r11.Options242394{
				GroupByLabels: []string{"foo"},
			},
			[][]string{{"", "foo"}, {"", ""}},
			[][]error{{nil, nil}, {nil, errors.New(" foo NO such file or directory  ")}},
			[]rule.CheckResult{
				rule.PassedCheckResult("SSH daemon disabled (or could not be probed)", rule.NewTarget("kind", "node", "name", "node1")),
				rule.PassedCheckResult("SSH daemon service not installed", rule.NewTarget("kind", "node", "name", "node3")),
				rule.WarningCheckResult("Node is missing a label", rule.NewTarget("kind", "node", "name", "node4", "label", "foo")),
			}),
		Entry("should return correct checkResults when commands error", nil,
			[][]string{{""}, {"", "foo"},
				{"", "foo"}, {"", ""}},
			[][]error{{errors.New("foo")}, {nil, errors.New("bar")}, {nil, nil}, {nil, errors.New(" foo NO such file or directory  ")}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242394-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242394-bbbbbbbbbb", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("SSH daemon disabled (or could not be probed)", rule.NewTarget("kind", "node", "name", "node3")),
				rule.PassedCheckResult("SSH daemon service not installed", rule.NewTarget("kind", "node", "name", "node4")),
			}),
	)
})
