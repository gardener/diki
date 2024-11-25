// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var _ = Describe("#2001", func() {
	var (
		client        client.Client
		plainPod      *corev1.Pod
		ctx           = context.TODO()
		namespaceName = "foo"
		namespace     *corev1.Namespace
	)

	BeforeEach(func() {
		client = fakeclient.NewClientBuilder().Build()
		namespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
		}
		plainPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: namespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:            "test",
						SecurityContext: &corev1.SecurityContext{},
					},
				},
			},
		}
	})

	DescribeTable("Run cases",
		func(securityContext *corev1.SecurityContext, ruleOptions rules.Options2001, expectedResult rule.CheckResult) {
			r := &rules.Rule2001{Client: client, Options: &ruleOptions}
			pod := plainPod.DeepCopy()
			pod.Spec.Containers[0].SecurityContext = securityContext

			Expect(client.Create(ctx, pod)).To(Succeed())
			Expect(client.Create(ctx, namespace)).To(Succeed())

			ruleResult, err := r.Run(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{expectedResult}))
		},

		Entry("should fail when securityContext is not set",
			nil, rules.Options2001{},
			rule.CheckResult{Status: rule.Failed, Message: "Pod must not escalate privileges.", Target: rule.NewTarget("kind", "pod", "name", "foo", "namespace", "foo", "container", "test")},
		),
		Entry("should fail when allowPrivilegeEscalation is not set",
			&corev1.SecurityContext{}, rules.Options2001{},
			rule.CheckResult{Status: rule.Failed, Message: "Pod must not escalate privileges.", Target: rule.NewTarget("kind", "pod", "name", "foo", "namespace", "foo", "container", "test")},
		),
		Entry("should fail when allowPrivilegeEscalation is set to true",
			&corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(true)}, rules.Options2001{},
			rule.CheckResult{Status: rule.Failed, Message: "Pod must not escalate privileges.", Target: rule.NewTarget("kind", "pod", "name", "foo", "namespace", "foo", "container", "test")},
		),
		Entry("should pass when allowPrivilegeEscalation is set to false",
			&corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false)}, rules.Options2001{},
			rule.CheckResult{Status: rule.Passed, Message: "Pod does not escalate privileges.", Target: rule.NewTarget("kind", "pod", "name", "foo", "namespace", "foo")},
		),
		Entry("should fail when privileged is set to true",
			&corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), Privileged: ptr.To(true)}, rules.Options2001{},
			rule.CheckResult{Status: rule.Failed, Message: "Pod must not escalate privileges.", Target: rule.NewTarget("kind", "pod", "name", "foo", "namespace", "foo", "container", "test")},
		),
		Entry("should fail when SYS_ADMIN capability is added",
			&corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}}}, rules.Options2001{},
			rule.CheckResult{Status: rule.Failed, Message: "Pod must not escalate privileges.", Target: rule.NewTarget("kind", "pod", "name", "foo", "namespace", "foo", "container", "test")},
		),
		Entry("should fail when CAP_SYS_ADMIN capability is added",
			&corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"CAP_SYS_ADMIN"}}}, rules.Options2001{},
			rule.CheckResult{Status: rule.Failed, Message: "Pod must not escalate privileges.", Target: rule.NewTarget("kind", "pod", "name", "foo", "namespace", "foo", "container", "test")},
		),
		Entry("should pass when options are set",
			&corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(true)},
			rules.Options2001{
				AcceptedPods: []rules.AcceptedPods2001{
					{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							MatchLabels:          map[string]string{"foo": "bar"},
							NamespaceMatchLabels: map[string]string{"foo": "bar"},
						},
						Justification: "foo justify",
					},
				},
			},
			rule.CheckResult{Status: rule.Accepted, Message: "foo justify", Target: rule.NewTarget("kind", "pod", "name", "foo", "namespace", "foo", "container", "test")},
		),
	)
})
