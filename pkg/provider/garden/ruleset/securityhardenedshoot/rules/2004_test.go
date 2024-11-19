// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/garden/ruleset/securityhardenedshoot/rules"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#2004", func() {
	var (
		fakeClient     client.Client
		ctx            = context.TODO()
		shootName      = "foo"
		shootNamespace = "bar"

		shoot *gardencorev1beta1.Shoot

		r                          rule.Rule
		ruleName                   = "Shoot clusters must have ValidatingAdmissionWebhook admission plugin enabled."
		ruleID                     = "2004"
		severity                   = rule.SeverityHigh
		validatingAdmissionWebhook = "ValidatingAdmissionWebhook"
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.GardenScheme).Build()
		shoot = &gardencorev1beta1.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      shootName,
				Namespace: shootNamespace,
			},
		}
		r = &rules.Rule2004{
			Client:         fakeClient,
			ShootName:      shootName,
			ShootNamespace: shootNamespace,
		}
	})

	DescribeTable("Run cases", func(updateFn func(), expectedCheckResult rule.CheckResult) {
		updateFn()
		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())
		res, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(Equal(rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: severity, CheckResults: []rule.CheckResult{expectedCheckResult}}))
	},
		Entry("should error when the shoot can't be found",
			func() { shoot.Name = "notFoo" },
			rule.CheckResult{Status: rule.Errored, Message: "shoots.core.gardener.cloud \"foo\" not found", Target: rule.NewTarget("name", "foo", "namespace", "bar", "kind", "Shoot")},
		),
		Entry("should pass when the kube-apiserver is set by default",
			func() {
				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{}
			},
			rule.CheckResult{Status: rule.Passed, Message: "The validating admission webhook is not disabled.", Target: rule.NewTarget()},
		),
		Entry("should pass when the kube-apiserver's admission plugins are set by default",
			func() {
				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{},
				}
			},
			rule.CheckResult{Status: rule.Passed, Message: "The validating admission webhook is not disabled.", Target: rule.NewTarget()},
		),
		Entry("should pass when the kube-apiserver's validating admission webhook is not set",
			func() {
				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name: "foo",
						},
					},
				}
			},
			rule.CheckResult{Status: rule.Passed, Message: "The validating admission webhook is not disabled.", Target: rule.NewTarget()},
		),
		Entry("should pass when the kube-apiserver's validating admission webhook isn't enabled explicitly",
			func() {
				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name:     validatingAdmissionWebhook,
							Disabled: nil,
						},
					},
				}
			},
			rule.CheckResult{Status: rule.Passed, Message: "The validating admission webhook is not disabled.", Target: rule.NewTarget()},
		),
		Entry("should pass when the kube-apiserver's validating admission webhook is enabled explicitly",
			func() {
				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name:     validatingAdmissionWebhook,
							Disabled: ptr.To(false),
						},
					},
				}
			},
			rule.CheckResult{Status: rule.Passed, Message: "The validating admission webhook is enabled.", Target: rule.NewTarget()},
		),
		Entry("should fail when the kube-apiserver's validating admission webhook is enabled explicitly",
			func() {
				shoot.Spec.Kubernetes.KubeAPIServer = &gardencorev1beta1.KubeAPIServerConfig{
					AdmissionPlugins: []gardencorev1beta1.AdmissionPlugin{
						{
							Name:     validatingAdmissionWebhook,
							Disabled: ptr.To(true),
						},
					},
				}
			},
			rule.CheckResult{Status: rule.Failed, Message: "The validating admission webhook is disabled.", Target: rule.NewTarget()},
		),
	)
})
