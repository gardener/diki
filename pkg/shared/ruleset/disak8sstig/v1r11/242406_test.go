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
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

var _ = Describe("#242406", func() {
	const (
		kubeletServicePath                       = "/etc/systemd/system/kubelet.service"
		compliantKubeletServiceFileStats         = "644\t0\t0\tregular file\t/etc/systemd/system/kubelet.service"
		nonCompliantKubeletServiceFileStats      = "644\t1000\t2000\tregular file\t/etc/systemd/system/kubelet.service"
		nonCompliantUserKubeletServiceFileStats  = "644\t1000\t0\tregular file\t/etc/systemd/system/kubelet.service"
		nonCompliantGroupKubeletServiceFileStats = "644\t0\t1000\tregular file\t/etc/systemd/system/kubelet.service"
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
		sharedv1r11.Generator = &fakestrgen.FakeRandString{Rune: 'a'}
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
		func(options sharedv1r11.Options242406, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			podContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &sharedv1r11.Rule242406{
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
			[][]string{{kubeletServicePath, compliantKubeletServiceFileStats}, {kubeletServicePath, nonCompliantKubeletServiceFileStats},
				{kubeletServicePath, nonCompliantUserKubeletServiceFileStats}, {kubeletServicePath, nonCompliantGroupKubeletServiceFileStats}},
			[][]error{{nil, nil}, {nil, nil}, {nil, nil}, {nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "node", "name", "node1", "details", "fileName: /etc/systemd/system/kubelet.service, ownerUser: 0, ownerGroup: 0")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("kind", "node", "name", "node2", "details", "fileName: /etc/systemd/system/kubelet.service, ownerUser: 1000, expectedOwnerUsers: [0]")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("kind", "node", "name", "node2", "details", "fileName: /etc/systemd/system/kubelet.service, ownerGroup: 2000, expectedOwnerGroups: [0]")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("kind", "node", "name", "node3", "details", "fileName: /etc/systemd/system/kubelet.service, ownerUser: 1000, expectedOwnerUsers: [0]")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("kind", "node", "name", "node4", "details", "fileName: /etc/systemd/system/kubelet.service, ownerGroup: 1000, expectedOwnerGroups: [0]")),
			}),
		Entry("should return correct checkResults only for selected nodes",
			sharedv1r11.Options242406{
				NodeGroupByLabels: []string{"foo"},
			},
			[][]string{{kubeletServicePath, compliantKubeletServiceFileStats}, {kubeletServicePath, compliantKubeletServiceFileStats}},
			[][]error{{nil, nil}, {nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "node", "name", "node1", "details", "fileName: /etc/systemd/system/kubelet.service, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "node", "name", "node3", "details", "fileName: /etc/systemd/system/kubelet.service, ownerUser: 0, ownerGroup: 0")),
				rule.WarningCheckResult("Node is missing a label", rule.NewTarget("kind", "node", "name", "node4", "label", "foo")),
			}),
		Entry("should return correct checkResults when expected owners are specified",
			sharedv1r11.Options242406{
				FileOwnerOptions: &option.FileOwnerOptions{
					ExpectedFileOwner: option.ExpectedOwner{
						Users:  []string{"0", "1000"},
						Groups: []string{"0", "2000"},
					},
				},
			},
			[][]string{{kubeletServicePath, compliantKubeletServiceFileStats}, {kubeletServicePath, nonCompliantKubeletServiceFileStats},
				{kubeletServicePath, nonCompliantUserKubeletServiceFileStats}, {kubeletServicePath, nonCompliantGroupKubeletServiceFileStats}},
			[][]error{{nil, nil}, {nil, nil}, {nil, nil}, {nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "node", "name", "node1", "details", "fileName: /etc/systemd/system/kubelet.service, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "node", "name", "node2", "details", "fileName: /etc/systemd/system/kubelet.service, ownerUser: 1000, ownerGroup: 2000")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "node", "name", "node3", "details", "fileName: /etc/systemd/system/kubelet.service, ownerUser: 1000, ownerGroup: 0")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("kind", "node", "name", "node4", "details", "fileName: /etc/systemd/system/kubelet.service, ownerGroup: 1000, expectedOwnerGroups: [0 2000]")),
			}),
		Entry("should return correct checkResults when commands error", nil,
			[][]string{{kubeletServicePath}, {kubeletServicePath, ""},
				{kubeletServicePath, compliantKubeletServiceFileStats}, {kubeletServicePath, compliantKubeletServiceFileStats}},
			[][]error{{errors.New("foo")}, {nil, errors.New("bar")}, {nil, nil}, {nil, nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("could not find kubelet.service path: foo", rule.NewTarget("name", "diki-242406-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.ErroredCheckResult("bar", rule.NewTarget("name", "diki-242406-bbbbbbbbbb", "namespace", "kube-system", "kind", "pod")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "node", "name", "node3", "details", "fileName: /etc/systemd/system/kubelet.service, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("kind", "node", "name", "node4", "details", "fileName: /etc/systemd/system/kubelet.service, ownerUser: 0, ownerGroup: 0")),
			}),
	)
})
