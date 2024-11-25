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
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
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
		func(serviceSpec corev1.ServiceSpec, ruleOptions rules.Options2004, expectedResult rule.CheckResult) {
			r := &rules.Rule2004{Client: client, Options: &ruleOptions}
			service.Spec = serviceSpec

			Expect(client.Create(ctx, service)).To(Succeed())
			Expect(client.Create(ctx, namespace)).To(Succeed())

			ruleResult, err := r.Run(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{expectedResult}))
		},

		Entry("should pass when serviceSpec is not set",
			corev1.ServiceSpec{}, rules.Options2004{},
			rule.CheckResult{Status: rule.Passed, Message: "Service is not of type nodePort.", Target: rule.NewTarget("kind", "service", "name", "foo", "namespace", "foo")},
		),
		Entry("should fail when service is of type NodePort",
			corev1.ServiceSpec{Type: "NodePort"}, rules.Options2004{},
			rule.CheckResult{Status: rule.Failed, Message: "Service should not be of type nodePort.", Target: rule.NewTarget("kind", "service", "name", "foo", "namespace", "foo")},
		),
		Entry("should pass when service is not of type NodePort",
			corev1.ServiceSpec{Type: "ClusterIP"}, rules.Options2004{},
			rule.CheckResult{Status: rule.Passed, Message: "Service is not of type nodePort.", Target: rule.NewTarget("kind", "service", "name", "foo", "namespace", "foo")},
		),
		Entry("should pass when options are set",
			corev1.ServiceSpec{Type: "NodePort"},
			rules.Options2004{
				AcceptedServices: []rules.AcceptedServices2004{
					{
						ServiceSelector: option.ServiceSelector{
							ServiceMatchLabels:   map[string]string{"foo": "bar"},
							NamespaceMatchLabels: map[string]string{"foo": "bar"},
						},
						Justification: "foo justify",
					},
				},
			},
			rule.CheckResult{Status: rule.Accepted, Message: "foo justify", Target: rule.NewTarget("kind", "service", "name", "foo", "namespace", "foo")},
		),
	)
})
