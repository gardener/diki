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

var _ = Describe("#2002", func() {
	var (
		fakeClient     client.Client
		ctx            = context.TODO()
		shootName      = "foo"
		shootNamespace = "bar"

		shoot *gardencorev1beta1.Shoot

		r        rule.Rule
		ruleName = "Shoot clusters must not have Alpha APIs enabled for any Kubernetes component."
		ruleID   = "2002"
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
		r = &rules.Rule2002{
			ShootName:      shootName,
			ShootNamespace: shootNamespace,
			Client:         fakeClient,
		}
	})

	DescribeTable("Run cases", func(updateFn func(), expectedCheckResult []rule.CheckResult) {
		updateFn()

		Expect(fakeClient.Create(ctx, shoot)).To(Succeed())

		res, err := r.Run(ctx)
		Expect(err).To(BeNil())

		expectedResult := rule.RuleResult{RuleID: ruleID, RuleName: ruleName, Severity: severity, CheckResults: expectedCheckResult}
		Expect(res).To(Equal(expectedResult))
	},
		Entry("should error when the shoot is not found",
			func() { shoot.Name = "notFoo" },
			[]rule.CheckResult{
				{Status: rule.Errored, Message: "shoots.core.gardener.cloud \"foo\" not found", Target: rule.NewTarget("kind", "Shoot", "name", "foo", "namespace", "bar")},
			},
		),
		Entry("should pass when AllAlpha featureGates are set to default for all components",
			func() {},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "AllAlpha featureGates are not enabled for the kube apiserver.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are not enabled for the kube controller manager.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are not enabled for the kube scheduler.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are not enabled for the kube proxy.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are not enabled for the kubelet.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when AllAlpha featureGates are enabled for all components",
			func() {
				shoot.Spec.Kubernetes.KubeAPIServer = ptr.To(gardencorev1beta1.KubeAPIServerConfig{KubernetesConfig: gardencorev1beta1.KubernetesConfig{FeatureGates: map[string]bool{"AllAlpha": true}}})
				shoot.Spec.Kubernetes.KubeControllerManager = ptr.To(gardencorev1beta1.KubeControllerManagerConfig{KubernetesConfig: gardencorev1beta1.KubernetesConfig{FeatureGates: map[string]bool{"AllAlpha": true}}})
				shoot.Spec.Kubernetes.KubeScheduler = ptr.To(gardencorev1beta1.KubeSchedulerConfig{KubernetesConfig: gardencorev1beta1.KubernetesConfig{FeatureGates: map[string]bool{"AllAlpha": true}}})
				shoot.Spec.Kubernetes.KubeProxy = ptr.To(gardencorev1beta1.KubeProxyConfig{KubernetesConfig: gardencorev1beta1.KubernetesConfig{FeatureGates: map[string]bool{"AllAlpha": true}}})
				shoot.Spec.Kubernetes.Kubelet = ptr.To(gardencorev1beta1.KubeletConfig{KubernetesConfig: gardencorev1beta1.KubernetesConfig{FeatureGates: map[string]bool{"AllAlpha": true}}})
			},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "AllAlpha featureGates are enabled for the kube apiserver.", Target: rule.NewTarget()},
				{Status: rule.Failed, Message: "AllAlpha featureGates are enabled for the kube controller manager.", Target: rule.NewTarget()},
				{Status: rule.Failed, Message: "AllAlpha featureGates are enabled for the kube scheduler.", Target: rule.NewTarget()},
				{Status: rule.Failed, Message: "AllAlpha featureGates are enabled for the kube proxy.", Target: rule.NewTarget()},
				{Status: rule.Failed, Message: "AllAlpha featureGates are enabled for the kubelet.", Target: rule.NewTarget()},
			},
		),
		Entry("should pass when AllAlpha featureGates are disabled for all components",
			func() {
				shoot.Spec.Kubernetes.KubeAPIServer = ptr.To(gardencorev1beta1.KubeAPIServerConfig{KubernetesConfig: gardencorev1beta1.KubernetesConfig{FeatureGates: map[string]bool{"AllAlpha": false}}})
				shoot.Spec.Kubernetes.KubeControllerManager = ptr.To(gardencorev1beta1.KubeControllerManagerConfig{KubernetesConfig: gardencorev1beta1.KubernetesConfig{FeatureGates: map[string]bool{"AllAlpha": false}}})
				shoot.Spec.Kubernetes.KubeScheduler = ptr.To(gardencorev1beta1.KubeSchedulerConfig{KubernetesConfig: gardencorev1beta1.KubernetesConfig{FeatureGates: map[string]bool{"AllAlpha": false}}})
				shoot.Spec.Kubernetes.KubeProxy = ptr.To(gardencorev1beta1.KubeProxyConfig{KubernetesConfig: gardencorev1beta1.KubernetesConfig{FeatureGates: map[string]bool{"AllAlpha": false}}})
				shoot.Spec.Kubernetes.Kubelet = ptr.To(gardencorev1beta1.KubeletConfig{KubernetesConfig: gardencorev1beta1.KubernetesConfig{FeatureGates: map[string]bool{"AllAlpha": false}}})
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "AllAlpha featureGates are disabled for the kube apiserver.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are disabled for the kube controller manager.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are disabled for the kube scheduler.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are disabled for the kube proxy.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are disabled for the kubelet.", Target: rule.NewTarget()},
			},
		),
		Entry("should pass when AllAlpha featureGates are disabled for the kube proxy component",
			func() {
				shoot.Spec.Kubernetes.KubeProxy = ptr.To(gardencorev1beta1.KubeProxyConfig{KubernetesConfig: gardencorev1beta1.KubernetesConfig{FeatureGates: map[string]bool{"AllAlpha": false}}})
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "AllAlpha featureGates are not enabled for the kube apiserver.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are not enabled for the kube controller manager.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are not enabled for the kube scheduler.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are disabled for the kube proxy.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are not enabled for the kubelet.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when AllAlpha featureGates are disabled for the kubelet",
			func() {
				shoot.Spec.Kubernetes.Kubelet = ptr.To(gardencorev1beta1.KubeletConfig{KubernetesConfig: gardencorev1beta1.KubernetesConfig{FeatureGates: map[string]bool{"AllAlpha": true}}})
			},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "AllAlpha featureGates are not enabled for the kube apiserver.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are not enabled for the kube controller manager.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are not enabled for the kube scheduler.", Target: rule.NewTarget()},
				{Status: rule.Passed, Message: "AllAlpha featureGates are not enabled for the kube proxy.", Target: rule.NewTarget()},
				{Status: rule.Failed, Message: "AllAlpha featureGates are enabled for the kubelet.", Target: rule.NewTarget()},
			},
		),
	)
})
