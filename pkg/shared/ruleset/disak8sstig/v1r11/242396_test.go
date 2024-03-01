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

var _ = Describe("#242396", func() {
	const (
		allowedKubectlVersion     = `{"clientVersion": {"gitVersion": "v1.12.9"}}`
		notAllowedKubectlVersion  = `{"clientVersion": {"gitVersion": "v1.12.8"}}`
		emptyKubectlVersion       = `{}`
		emptyClientKubectlVersion = `{"clientVersion": {}}`
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
		func(options v1r11.Options242396, executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			podContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &v1r11.Rule242396{
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
			[][]string{{allowedKubectlVersion}, {notAllowedKubectlVersion},
				{emptyKubectlVersion}, {emptyClientKubectlVersion}},
			[][]error{{nil}, {nil}, {nil}, {nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("Node uses allowed kubectl version", rule.NewTarget("kind", "node", "name", "node1", "details", "Kubectl client version 1.12.9")),
				rule.FailedCheckResult("Node uses not allowed kubectl version", rule.NewTarget("kind", "node", "name", "node2", "details", "Kubectl client version 1.12.8")),
				rule.ErroredCheckResult("kubectl client version not preset in output", rule.NewTarget("name", "diki-242396-cccccccccc", "namespace", "kube-system", "kind", "pod", "output", "{}")),
				rule.ErroredCheckResult("kubectl client version not preset in output", rule.NewTarget("name", "diki-242396-dddddddddd", "namespace", "kube-system", "kind", "pod", "output", "{\"clientVersion\": {}}")),
			}),
		Entry("should return correct checkResults only for selected nodes",
			v1r11.Options242396{
				GroupByLabels: []string{"foo"},
			},
			[][]string{{allowedKubectlVersion}, {allowedKubectlVersion}},
			[][]error{{nil}, {nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("Node uses allowed kubectl version", rule.NewTarget("kind", "node", "name", "node1", "details", "Kubectl client version 1.12.9")),
				rule.PassedCheckResult("Node uses allowed kubectl version", rule.NewTarget("kind", "node", "name", "node3", "details", "Kubectl client version 1.12.9")),
				rule.WarningCheckResult("Node is missing a label", rule.NewTarget("kind", "node", "name", "node4", "label", "foo")),
			}),
		Entry("should return correct checkResults when commands error", nil,
			[][]string{{""}, {""},
				{allowedKubectlVersion}, {allowedKubectlVersion}},
			[][]error{{errors.New("foo")}, {errors.New("foo command terminated with exit code 127 bar ")}, {nil}, {nil}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", rule.NewTarget("name", "diki-242396-aaaaaaaaaa", "namespace", "kube-system", "kind", "pod")),
				rule.SkippedCheckResult("Kubectl command could not be found (or not installed)", rule.NewTarget("kind", "node", "name", "node2")),
				rule.PassedCheckResult("Node uses allowed kubectl version", rule.NewTarget("kind", "node", "name", "node3", "details", "Kubectl client version 1.12.9")),
				rule.PassedCheckResult("Node uses allowed kubectl version", rule.NewTarget("kind", "node", "name", "node4", "details", "Kubectl client version 1.12.9")),
			}),
	)
})
