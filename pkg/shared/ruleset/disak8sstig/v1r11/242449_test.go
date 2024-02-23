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

var _ = Describe("#242449", func() {
	const (
		kubeletPID                     = "1"
		rawKubeletCommand              = `--config=/var/lib/kubelet/config/kubelet`
		compliantClientCAFileStats     = "644\t0\t0\tregular file\t/var/lib/kubelet/ca.crt"
		nonCompliantClientCAFileStats1 = "664\t0\t0\tregular file\t/var/lib/kubelet/ca.crt"
		nonCompliantClientCAFileStats2 = "700\t0\t0\tregular file\t/var/lib/kubelet/ca.crt"
		nonCompliantClientCAFileStats3 = "606\t0\t0\tregular file\t/var/lib/kubelet/ca.crt"
		kubeletConfig                  = `authentication:
  x509:
    clientCAFile: /var/lib/kubelet/ca.crt`
	)
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
		func(options v1r11.Options242449, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			podContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &v1r11.Rule242449{
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
			[][]string{{kubeletPID, rawKubeletCommand, kubeletConfig, compliantClientCAFileStats}, {kubeletPID, rawKubeletCommand, kubeletConfig, nonCompliantClientCAFileStats1},
				{kubeletPID, rawKubeletCommand, kubeletConfig, nonCompliantClientCAFileStats2}, {kubeletPID, rawKubeletCommand, kubeletConfig, nonCompliantClientCAFileStats3}},
			[][]error{{nil, nil, nil, nil}, {nil, nil, nil, nil}, {nil, nil, nil, nil}, {nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("kind", "node", "name", "node1", "details", "fileName: /var/lib/kubelet/ca.crt, permissions: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("kind", "node", "name", "node2", "details", "fileName: /var/lib/kubelet/ca.crt, permissions: 664, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("kind", "node", "name", "node3", "details", "fileName: /var/lib/kubelet/ca.crt, permissions: 700, expectedPermissionsMax: 644")),
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("kind", "node", "name", "node4", "details", "fileName: /var/lib/kubelet/ca.crt, permissions: 606, expectedPermissionsMax: 644")),
			}),
		Entry("should return correct checkResults only for selected nodes",
			v1r11.Options242449{
				GroupByLabels: []string{"foo"},
			},
			[][]string{{kubeletPID, rawKubeletCommand, kubeletConfig, compliantClientCAFileStats}, {kubeletPID, rawKubeletCommand, kubeletConfig, compliantClientCAFileStats}},
			[][]error{{nil, nil, nil, nil}, {nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("kind", "node", "name", "node1", "details", "fileName: /var/lib/kubelet/ca.crt, permissions: 644")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("kind", "node", "name", "node3", "details", "fileName: /var/lib/kubelet/ca.crt, permissions: 644")),
				rule.WarningCheckResult("Node is missing a label", rule.NewTarget("kind", "node", "name", "node4", "label", "foo")),
			}),
		Entry("should return correct checkResults when commands error", nil,
			[][]string{{kubeletPID, rawKubeletCommand}, {kubeletPID, rawKubeletCommand, kubeletConfig},
				{kubeletPID, rawKubeletCommand, kubeletConfig, compliantClientCAFileStats}, {kubeletPID, rawKubeletCommand, kubeletConfig, compliantClientCAFileStats}},
			[][]error{{errors.New("foo")}, {nil, nil, errors.New("bar")}, {nil, nil, nil, errors.New("foo-bar")}, {nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242449-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("could not retrieve kubelet config: bar", rule.NewTarget("name", "diki-242449-bbbbbbbbbb", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("foo-bar", rule.NewTarget("name", "diki-242449-cccccccccc", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("kind", "node", "name", "node4", "details", "fileName: /var/lib/kubelet/ca.crt, permissions: 644")),
			}),
	)
})
