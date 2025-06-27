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
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#242450", func() {
	const (
		kubeletPID                     = "1"
		rawKubeletCommand              = `--config=/var/lib/kubelet/config/kubelet`
		compliantClientCAFileStats     = "644\t0\t0\tregular file\t/var/lib/kubelet/ca.crt"
		nonCompliantClientCAFileStats1 = "644\t1000\t2000\tregular file\t/var/lib/kubelet/ca.crt"
		nonCompliantClientCAFileStats2 = "644\t1000\t0\tregular file\t/var/lib/kubelet/ca.crt"
		nonCompliantClientCAFileStats3 = "644\t0\t1000\tregular file\t/var/lib/kubelet/ca.crt"
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
		func(options rules.Options242450, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			podContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &rules.Rule242450{
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
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "Node", "name", "node1", "details", "fileName: /var/lib/kubelet/ca.crt, ownerUser: 0, ownerGroup: 0")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("kind", "Node", "name", "node2", "details", "fileName: /var/lib/kubelet/ca.crt, ownerUser: 1000, expectedOwnerUsers: [0]")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("kind", "Node", "name", "node2", "details", "fileName: /var/lib/kubelet/ca.crt, ownerGroup: 2000, expectedOwnerGroups: [0]")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("kind", "Node", "name", "node3", "details", "fileName: /var/lib/kubelet/ca.crt, ownerUser: 1000, expectedOwnerUsers: [0]")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("kind", "Node", "name", "node4", "details", "fileName: /var/lib/kubelet/ca.crt, ownerGroup: 1000, expectedOwnerGroups: [0]")),
			}),
		Entry("should return correct checkResults only for selected nodes",
			rules.Options242450{
				NodeGroupByLabels: []string{"foo"},
			},
			[][]string{{kubeletPID, rawKubeletCommand, kubeletConfig, compliantClientCAFileStats}, {kubeletPID, rawKubeletCommand, kubeletConfig, compliantClientCAFileStats}},
			[][]error{{nil, nil, nil, nil}, {nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "Node", "name", "node1", "details", "fileName: /var/lib/kubelet/ca.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "Node", "name", "node3", "details", "fileName: /var/lib/kubelet/ca.crt, ownerUser: 0, ownerGroup: 0")),
				rule.WarningCheckResult("Node is missing a label", rule.NewTarget("kind", "Node", "name", "node4", "label", "foo")),
			}),
		Entry("should return correct checkResults when expected owners are specified",
			rules.Options242450{
				FileOwnerOptions: &option.FileOwnerOptions{
					ExpectedFileOwner: option.ExpectedOwner{
						Users:  []string{"0", "1000"},
						Groups: []string{"0", "2000"},
					},
				},
			},
			[][]string{{kubeletPID, rawKubeletCommand, kubeletConfig, compliantClientCAFileStats}, {kubeletPID, rawKubeletCommand, kubeletConfig, nonCompliantClientCAFileStats1},
				{kubeletPID, rawKubeletCommand, kubeletConfig, nonCompliantClientCAFileStats2}, {kubeletPID, rawKubeletCommand, kubeletConfig, nonCompliantClientCAFileStats3}},
			[][]error{{nil, nil, nil, nil}, {nil, nil, nil, nil}, {nil, nil, nil, nil}, {nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "Node", "name", "node1", "details", "fileName: /var/lib/kubelet/ca.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "Node", "name", "node2", "details", "fileName: /var/lib/kubelet/ca.crt, ownerUser: 1000, ownerGroup: 2000")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "Node", "name", "node3", "details", "fileName: /var/lib/kubelet/ca.crt, ownerUser: 1000, ownerGroup: 0")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("kind", "Node", "name", "node4", "details", "fileName: /var/lib/kubelet/ca.crt, ownerGroup: 1000, expectedOwnerGroups: [0 2000]")),
			}),
		Entry("should return correct checkResults when commands error", nil,
			[][]string{{kubeletPID, rawKubeletCommand}, {kubeletPID, rawKubeletCommand, kubeletConfig},
				{kubeletPID, rawKubeletCommand, kubeletConfig, compliantClientCAFileStats}, {kubeletPID, rawKubeletCommand, kubeletConfig, compliantClientCAFileStats}},
			[][]error{{errors.New("foo")}, {nil, nil, errors.New("bar")}, {nil, nil, nil, errors.New("foo-bar")}, {nil, nil, nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242450-aaaaaaaaaa", "namespace", "kube-system", "kind", "Pod")),
				rule.ErroredCheckResult("could not retrieve kubelet config: bar", rule.NewTarget("name", "diki-242450-bbbbbbbbbb", "namespace", "kube-system", "kind", "Pod")),
				rule.ErroredCheckResult("foo-bar", rule.NewTarget("name", "diki-242450-cccccccccc", "namespace", "kube-system", "kind", "Pod")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "Node", "name", "node4", "details", "fileName: /var/lib/kubelet/ca.crt, ownerUser: 0, ownerGroup: 0")),
			}),
	)
})
