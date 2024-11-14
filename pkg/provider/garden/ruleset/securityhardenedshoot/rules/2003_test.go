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

var _ = Describe("#2003", func() {
	var (
		fakeClient client.Client
		ctx        = context.TODO()
		shootName  = "bar"
		namespace  = "foo"

		shoot *gardencorev1beta1.Shoot

		r        rule.Rule
		ruleName = "Shoot clusters must enable kernel protection for Kubelets."
		ruleID   = "2003"
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.GardenScheme).Build()
		shoot = &gardencorev1beta1.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      shootName,
				Namespace: namespace,
			},
		}
		r = &rules.Rule2003{
			ShootName:      shootName,
			ShootNamespace: namespace,
			Client:         fakeClient,
		}

	})

	DescribeTable("Run cases",
		func(updateFn func(), expectedCheckResult []rule.CheckResult) {
			updateFn()

			Expect(fakeClient.Create(ctx, shoot)).To(Succeed())
			res, err := r.Run(ctx)
			Expect(err).ToNot(HaveOccurred())
			expectedResult := rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: rule.SeverityHigh, CheckResults: expectedCheckResult}
			Expect(res).To(Equal(expectedResult))
		},

		Entry("should error when shoot is not found",
			func() { shoot.Name = "one" },
			[]rule.CheckResult{{Status: rule.Errored, Message: "shoots.core.gardener.cloud \"bar\" not found", Target: rule.NewTarget("name", "bar", "namespace", "foo", "kind", "Shoot")}},
		),
		Entry("should pass when shoot does not set kubelet config",
			func() {},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Default kubelet config does not disable kernel protection.", Target: rule.NewTarget()}},
		),
		Entry("should pass when shoot sets default kubelet config",
			func() { shoot.Spec.Kubernetes.Kubelet = &gardencorev1beta1.KubeletConfig{} },
			[]rule.CheckResult{{Status: rule.Passed, Message: "Default kubelet config does not disable kernel protection.", Target: rule.NewTarget()}},
		),
		Entry("should pass when shoot enables kernel defaults protection in the default kubelet config",
			func() {
				shoot.Spec.Kubernetes.Kubelet = &gardencorev1beta1.KubeletConfig{
					ProtectKernelDefaults: ptr.To(true),
				}
			},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Default kubelet config enables kernel protection.", Target: rule.NewTarget()}},
		),
		Entry("should fail when shoot disables kernel defaults protection in the default kubelet config",
			func() {
				shoot.Spec.Kubernetes.Kubelet = &gardencorev1beta1.KubeletConfig{
					ProtectKernelDefaults: ptr.To(false),
				}
			},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Default kubelet config disables kernel protection.", Target: rule.NewTarget()}},
		),
		Entry("should pass when shoot worker does not set kubelet config",
			func() {
				shoot.Spec.Provider.Workers = []gardencorev1beta1.Worker{
					{
						Name: "worker1",
					},
				}
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Default kubelet config does not disable kernel protection.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "Worker kubelet config does not disable kernel protection.", Target: rule.NewTarget("worker", "worker1")},
			},
		),
		Entry("should pass when shoot worker does not set kubernetes config",
			func() {
				shoot.Spec.Provider.Workers = []gardencorev1beta1.Worker{
					{
						Name: "worker1",
					},
				}
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Default kubelet config does not disable kernel protection.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "Worker kubelet config does not disable kernel protection.", Target: rule.NewTarget("worker", "worker1")},
			},
		),
		Entry("should pass when shoot worker sets default kubernetes config",
			func() {
				shoot.Spec.Provider.Workers = []gardencorev1beta1.Worker{
					{
						Name:       "worker1",
						Kubernetes: &gardencorev1beta1.WorkerKubernetes{},
					},
				}
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Default kubelet config does not disable kernel protection.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "Worker kubelet config does not disable kernel protection.", Target: rule.NewTarget("worker", "worker1")},
			},
		),
		Entry("should pass when shoot worker sets default kubelet config",
			func() {
				shoot.Spec.Provider.Workers = []gardencorev1beta1.Worker{
					{
						Name:       "worker1",
						Kubernetes: &gardencorev1beta1.WorkerKubernetes{},
					},
				}
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Default kubelet config does not disable kernel protection.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "Worker kubelet config does not disable kernel protection.", Target: rule.NewTarget("worker", "worker1")},
			},
		),
		Entry("should pass when shoot worker enables kernel defaults protection in kubelet config",
			func() {
				shoot.Spec.Provider.Workers = []gardencorev1beta1.Worker{
					{
						Name: "worker1",
						Kubernetes: &gardencorev1beta1.WorkerKubernetes{
							Kubelet: &gardencorev1beta1.KubeletConfig{
								ProtectKernelDefaults: ptr.To(true),
							},
						},
					},
				}
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Default kubelet config does not disable kernel protection.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "Worker kubelet config enables kernel protection.", Target: rule.NewTarget("worker", "worker1")},
			},
		),
		Entry("should fail when shoot worker disables kernel defaults protection in kubelet config",
			func() {
				shoot.Spec.Provider.Workers = []gardencorev1beta1.Worker{
					{
						Name: "worker1",
						Kubernetes: &gardencorev1beta1.WorkerKubernetes{
							Kubelet: &gardencorev1beta1.KubeletConfig{
								ProtectKernelDefaults: ptr.To(false),
							},
						},
					},
				}
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "Default kubelet config does not disable kernel protection.", Target: rule.NewTarget()},
				{Status: rule.Failed, Message: "Worker kubelet config disables kernel protection.", Target: rule.NewTarget("worker", "worker1")},
			},
		),
	)
})
