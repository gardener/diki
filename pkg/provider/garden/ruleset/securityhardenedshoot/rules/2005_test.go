// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"
	"time"

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

var _ = Describe("#2005", func() {
	var (
		fakeClient     client.Client
		ctx            = context.TODO()
		shootName      = "foo"
		shootNamespace = "bar"

		shoot *gardencorev1beta1.Shoot

		r        rule.Rule
		ruleName = "Shoot clusters must not disable timeouts for Kubelet."
		ruleID   = "2005"
		severity = rule.SeverityMedium
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.GardenScheme).Build()
		shoot = &gardencorev1beta1.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      shootName,
				Namespace: shootNamespace,
			},
		}
		r = &rules.Rule2005{
			Client:         fakeClient,
			ShootName:      shootName,
			ShootNamespace: shootNamespace,
		}
	})

	DescribeTable("Run cases", func(updateFn func(), expectedCheckResult []rule.CheckResult) {
		updateFn()
		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())
		res, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(res).To(Equal(rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: severity, CheckResults: expectedCheckResult}))
	},
		Entry("should error when the shoot can't be found",
			func() { shoot.Name = "notFoo" },
			[]rule.CheckResult{{Status: rule.Errored, Message: "shoots.core.gardener.cloud \"foo\" not found", Target: rule.NewTarget("name", "foo", "namespace", "bar", "kind", "Shoot")}},
		),
		Entry("should pass when the main kubelet has a default configuration",
			func() {},
			[]rule.CheckResult{{Status: rule.Passed, Message: "The connection timeout is not set and therefore will be defaulted to the recommended value (5m).", Target: rule.NewTarget()}},
		),
		Entry("should pass when the main kubelet has a default connection timeout",
			func() {
				shoot.Spec.Kubernetes.Kubelet = ptr.To(gardencorev1beta1.KubeletConfig{})
			},
			[]rule.CheckResult{{Status: rule.Passed, Message: "The connection timeout is not set and therefore will be defaulted to the recommended value (5m).", Target: rule.NewTarget()}},
		),
		Entry("should pass when the main kubelet has a connection timeout set to 5m",
			func() {
				duration, err := time.ParseDuration("5m")
				Expect(err).To(BeNil())

				shoot.Spec.Kubernetes.Kubelet = ptr.To(gardencorev1beta1.KubeletConfig{
					StreamingConnectionIdleTimeout: &metav1.Duration{
						Duration: duration,
					},
				})
			},
			[]rule.CheckResult{{Status: rule.Passed, Message: "The connection timeout is set to the recommended value (5m).", Target: rule.NewTarget()}},
		),
		Entry("should pass when the main kubelet has a connection timeout set in the interval between 5m and 4h",
			func() {
				duration, err := time.ParseDuration("2h45m")
				Expect(err).To(BeNil())

				shoot.Spec.Kubernetes.Kubelet = ptr.To(gardencorev1beta1.KubeletConfig{
					StreamingConnectionIdleTimeout: &metav1.Duration{
						Duration: duration,
					},
				})
			},
			[]rule.CheckResult{{Status: rule.Passed, Message: "The connection timeout is set to an allowed, but not recommended value (should be 5m).", Target: rule.NewTarget()}},
		),
		Entry("should fail when the main kubelet has a connection timeout set below 5m",
			func() {
				duration, err := time.ParseDuration("3s")
				Expect(err).To(BeNil())

				shoot.Spec.Kubernetes.Kubelet = ptr.To(gardencorev1beta1.KubeletConfig{
					StreamingConnectionIdleTimeout: &metav1.Duration{
						Duration: duration,
					},
				})
			},
			[]rule.CheckResult{{Status: rule.Failed, Message: "The connection timeout is set to a not allowed value (< 5m).", Target: rule.NewTarget()}},
		),
		Entry("should fail when the main kubelet has a connection timeout set above 4h",
			func() {
				duration, err := time.ParseDuration("5h12s")
				Expect(err).To(BeNil())

				shoot.Spec.Kubernetes.Kubelet = ptr.To(gardencorev1beta1.KubeletConfig{
					StreamingConnectionIdleTimeout: &metav1.Duration{
						Duration: duration,
					},
				})
			},
			[]rule.CheckResult{{Status: rule.Failed, Message: "The connection timeout is set to a not an allowed value (> 4h).", Target: rule.NewTarget()}},
		),
		Entry("should return appropriate check results for varying worker node configurations",
			func() {
				recommendedDuration, err := time.ParseDuration("5m")
				Expect(err).To(BeNil())
				belowValidDuration, err := time.ParseDuration("19s")
				Expect(err).To(BeNil())
				validDuration, err := time.ParseDuration("3h57m")
				Expect(err).To(BeNil())
				aboveValidDuration, err := time.ParseDuration("5h")
				Expect(err).To(BeNil())

				shoot.Spec.Provider.Workers = []gardencorev1beta1.Worker{
					{
						Name:       "worker1",
						Kubernetes: &gardencorev1beta1.WorkerKubernetes{},
					},
					{
						Name: "worker2",
						Kubernetes: &gardencorev1beta1.WorkerKubernetes{
							Kubelet: &gardencorev1beta1.KubeletConfig{},
						},
					},
					{
						Name: "worker3",
						Kubernetes: &gardencorev1beta1.WorkerKubernetes{
							Kubelet: &gardencorev1beta1.KubeletConfig{
								StreamingConnectionIdleTimeout: &metav1.Duration{
									Duration: recommendedDuration,
								},
							},
						},
					},
					{
						Name: "worker4",
						Kubernetes: &gardencorev1beta1.WorkerKubernetes{
							Kubelet: &gardencorev1beta1.KubeletConfig{
								StreamingConnectionIdleTimeout: &metav1.Duration{
									Duration: belowValidDuration,
								},
							},
						},
					},
					{
						Name: "worker5",
						Kubernetes: &gardencorev1beta1.WorkerKubernetes{
							Kubelet: &gardencorev1beta1.KubeletConfig{
								StreamingConnectionIdleTimeout: &metav1.Duration{
									Duration: validDuration,
								},
							},
						},
					},
					{
						Name: "worker6",
						Kubernetes: &gardencorev1beta1.WorkerKubernetes{
							Kubelet: &gardencorev1beta1.KubeletConfig{
								StreamingConnectionIdleTimeout: &metav1.Duration{
									Duration: aboveValidDuration,
								},
							},
						},
					},
				}
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "The connection timeout is not set and therefore will be defaulted to the recommended value (5m).", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "The connection timeout is not set and therefore will be defaulted to the recommended value (5m).", Target: rule.NewTarget("worker", "worker1")},
				{Status: rule.Passed, Message: "The connection timeout is not set and therefore will be defaulted to the recommended value (5m).", Target: rule.NewTarget("worker", "worker2")},
				{Status: rule.Passed, Message: "The connection timeout is set to the recommended value (5m).", Target: rule.NewTarget("worker", "worker3")},
				{Status: rule.Failed, Message: "The connection timeout is set to a not allowed value (< 5m).", Target: rule.NewTarget("worker", "worker4")},
				{Status: rule.Passed, Message: "The connection timeout is set to an allowed, but not recommended value (should be 5m).", Target: rule.NewTarget("worker", "worker5")},
				{Status: rule.Failed, Message: "The connection timeout is set to a not an allowed value (> 4h).", Target: rule.NewTarget("worker", "worker6")},
			},
		),
	)
})
