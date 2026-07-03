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
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
	"github.com/gardener/diki/pkg/shared/kubernetes/option/mergetest"
)

var _ = Describe("#2004", func() {
	var (
		client        client.Client
		service       *corev1.Service
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
		service = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: namespaceName,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
		}
	})

	DescribeTable("Run cases",
		func(updateFn func(), ruleOptions rules.Options2004, expectedResult rule.CheckResult) {
			updateFn()

			r := &rules.Rule2004{Client: client, Options: &ruleOptions}
			ruleResult, err := r.Run(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{expectedResult}))
		},
		Entry("should pass when no services are set",
			func() {}, rules.Options2004{},
			rule.CheckResult{Status: rule.Passed, Message: "The cluster does not have any Services.", Target: rule.NewTarget()},
		),
		Entry("should pass when serviceSpec is not set",
			func() {
				service.Spec = corev1.ServiceSpec{}
				Expect(client.Create(ctx, service)).To(Succeed())
				Expect(client.Create(ctx, namespace)).To(Succeed())

			}, rules.Options2004{},
			rule.CheckResult{Status: rule.Passed, Message: "Service is not of type NodePort.", Target: rule.NewTarget("kind", "Service", "name", "foo", "namespace", "foo")},
		),
		Entry("should fail when service is of type NodePort",
			func() {
				service.Spec = corev1.ServiceSpec{Type: "NodePort"}
				Expect(client.Create(ctx, service)).To(Succeed())
				Expect(client.Create(ctx, namespace)).To(Succeed())

			}, rules.Options2004{},
			rule.CheckResult{Status: rule.Failed, Message: "Service should not be of type NodePort.", Target: rule.NewTarget("kind", "Service", "name", "foo", "namespace", "foo")},
		),
		Entry("should pass when service is not of type NodePort",
			func() {
				service.Spec = corev1.ServiceSpec{Type: "ClusterIP"}
				Expect(client.Create(ctx, service)).To(Succeed())
				Expect(client.Create(ctx, namespace)).To(Succeed())

			}, rules.Options2004{},
			rule.CheckResult{Status: rule.Passed, Message: "Service is not of type NodePort.", Target: rule.NewTarget("kind", "Service", "name", "foo", "namespace", "foo")},
		),
		Entry("should pass when options are set",
			func() {
				service.Spec = corev1.ServiceSpec{Type: "NodePort"}
				Expect(client.Create(ctx, service)).To(Succeed())
				Expect(client.Create(ctx, namespace)).To(Succeed())

			},
			rules.Options2004{
				AcceptedServices: []option.AcceptedNamespacedObject{
					{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
							NamespaceLabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
						Justification: "foo justify",
					},
				},
			},
			rule.CheckResult{Status: rule.Accepted, Message: "foo justify", Target: rule.NewTarget("kind", "Service", "name", "foo", "namespace", "foo")},
		),
	)

	Describe("#Merge Options2004", func() {
		It("should merge two Options2004 by appending AcceptedServices", func() {
			base := &rules.Options2004{
				AcceptedServices: []option.AcceptedNamespacedObject{
					{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							LabelSelector:          &metav1.LabelSelector{MatchLabels: map[string]string{"app": "base"}},
							NamespaceLabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"ns": "base"}},
						},
						Justification: "base justification",
					},
				},
			}

			override := &rules.Options2004{
				AcceptedServices: []option.AcceptedNamespacedObject{
					{
						NamespacedObjectSelector: option.NamespacedObjectSelector{
							LabelSelector:          &metav1.LabelSelector{MatchLabels: map[string]string{"app": "override"}},
							NamespaceLabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"ns": "override"}},
						},
						Justification: "override justification",
					},
				},
			}

			merged, err := base.Merge(override)
			Expect(err).ToNot(HaveOccurred())

			mergedOpts, ok := merged.(*rules.Options2004)
			Expect(ok).To(BeTrue())
			Expect(mergedOpts.AcceptedServices).To(HaveLen(2))
			Expect(mergedOpts.AcceptedServices[0].Justification).To(Equal("base justification"))
			Expect(mergedOpts.AcceptedServices[1].Justification).To(Equal("override justification"))
		})

		It("should handle merging two empty Options2004", func() {
			base := &rules.Options2004{}
			other := &rules.Options2004{}

			merged, err := base.Merge(other)
			Expect(err).ToNot(HaveOccurred())

			mergedOpts, ok := merged.(*rules.Options2004)
			Expect(ok).To(BeTrue())
			Expect(mergedOpts.AcceptedServices).To(BeEmpty())
		})

		mergetest.AssertNilOtherReturnsReceiver(&rules.Options2004{
			AcceptedServices: []option.AcceptedNamespacedObject{{Justification: "base"}},
		})
		mergetest.AssertWrongTypeErrors(&rules.Options2004{}, &rules.Options2000{})
	})
})
