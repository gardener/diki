// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8_test

import (
	"context"

	"github.com/Masterminds/semver"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r8"
	dikirule "github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242437", func() {
	var (
		fakeSeedClient       client.Client
		fakeShootClient      client.Client
		kubernetesVersion124 *semver.Version
		kubernetesVersion125 *semver.Version
		seedPSP              *policyv1beta1.PodSecurityPolicy
		shootPSP             *policyv1beta1.PodSecurityPolicy
		ctx                  = context.TODO()
		namespace            = "foo"
	)

	BeforeEach(func() {
		fakeSeedClient = fakeclient.NewClientBuilder().Build()
		fakeShootClient = fakeclient.NewClientBuilder().Build()
		seedPSP = &policyv1beta1.PodSecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "seed-psp",
			},
			Spec: policyv1beta1.PodSecurityPolicySpec{
				FSGroup: policyv1beta1.FSGroupStrategyOptions{
					Ranges: []policyv1beta1.IDRange{
						{
							Min: 100,
						},
					},
				},
				SupplementalGroups: policyv1beta1.SupplementalGroupsStrategyOptions{
					Ranges: []policyv1beta1.IDRange{
						{
							Min: 100,
						},
					},
				},
				RunAsUser: policyv1beta1.RunAsUserStrategyOptions{
					Rule: "MustRunAsNonRoot",
				},
			},
		}
		shootPSP = &policyv1beta1.PodSecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "shoot-psp",
			},
			Spec: policyv1beta1.PodSecurityPolicySpec{
				FSGroup: policyv1beta1.FSGroupStrategyOptions{
					Ranges: []policyv1beta1.IDRange{
						{
							Min: 100,
						},
					},
				},
				SupplementalGroups: policyv1beta1.SupplementalGroupsStrategyOptions{
					Ranges: []policyv1beta1.IDRange{
						{
							Min: 100,
						},
					},
				},
				RunAsUser: policyv1beta1.RunAsUserStrategyOptions{
					Rule: "MustRunAsNonRoot",
				},
			},
		}

		kubernetesVersion124 = semver.MustParse("1.24.0")
		kubernetesVersion125 = semver.MustParse("1.25.0")
	})

	It("should return correct results when all PSPs pass", func() {
		rule := &v1r8.Rule242437{
			Logger:                testLogger,
			ClusterClient:         fakeShootClient,
			ClusterVersion:        kubernetesVersion124,
			ControlPlaneClient:    fakeSeedClient,
			ControlPlaneVersion:   kubernetesVersion124,
			ControlPlaneNamespace: namespace,
		}
		Expect(fakeSeedClient.Create(ctx, seedPSP)).To(Succeed())
		Expect(fakeShootClient.Create(ctx, shootPSP)).To(Succeed())

		ruleResult, err := rule.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []dikirule.CheckResult{
			{
				Status:  dikirule.Passed,
				Message: "Pod security policy correctly configured.",
				Target:  gardener.NewTarget("cluster", "seed", "name", "seed-psp", "kind", "podSecurityPolicy"),
			},
			{
				Status:  dikirule.Passed,
				Message: "Pod security policy correctly configured.",
				Target:  gardener.NewTarget("cluster", "shoot", "name", "shoot-psp", "kind", "podSecurityPolicy"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when all PSPs fail with fs group", func() {
		rule := &v1r8.Rule242437{
			Logger:                testLogger,
			ClusterClient:         fakeShootClient,
			ClusterVersion:        kubernetesVersion124,
			ControlPlaneClient:    fakeSeedClient,
			ControlPlaneVersion:   kubernetesVersion124,
			ControlPlaneNamespace: namespace,
		}
		seedPSP.Spec.FSGroup.Ranges = []policyv1beta1.IDRange{
			{
				Min: 0,
			},
		}
		Expect(fakeSeedClient.Create(ctx, seedPSP)).To(Succeed())
		shootPSP.Spec.FSGroup.Ranges = []policyv1beta1.IDRange{
			{
				Min: 1000,
			},
			{
				Min: 0,
			},
		}
		Expect(fakeShootClient.Create(ctx, shootPSP)).To(Succeed())

		ruleResult, err := rule.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []dikirule.CheckResult{
			{
				Status:  dikirule.Failed,
				Message: "Pod security policy fs group range not excluding 0.",
				Target:  gardener.NewTarget("cluster", "seed", "name", "seed-psp", "kind", "podSecurityPolicy"),
			},
			{
				Status:  dikirule.Failed,
				Message: "Pod security policy fs group range not excluding 0.",
				Target:  gardener.NewTarget("cluster", "shoot", "name", "shoot-psp", "kind", "podSecurityPolicy"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when PSPs do not have ranges set", func() {
		rule := &v1r8.Rule242437{
			Logger:                testLogger,
			ClusterClient:         fakeShootClient,
			ClusterVersion:        kubernetesVersion124,
			ControlPlaneClient:    fakeSeedClient,
			ControlPlaneVersion:   kubernetesVersion124,
			ControlPlaneNamespace: namespace,
		}
		seedPSP.Spec.FSGroup.Ranges = []policyv1beta1.IDRange{}
		Expect(fakeSeedClient.Create(ctx, seedPSP)).To(Succeed())
		shootPSP.Spec.SupplementalGroups.Ranges = []policyv1beta1.IDRange{}
		Expect(fakeShootClient.Create(ctx, shootPSP)).To(Succeed())

		ruleResult, err := rule.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []dikirule.CheckResult{
			{
				Status:  dikirule.Failed,
				Message: "Pod security policy fs group ranges are not set.",
				Target:  gardener.NewTarget("cluster", "seed", "name", "seed-psp", "kind", "podSecurityPolicy"),
			},
			{
				Status:  dikirule.Failed,
				Message: "Pod security policy supplemental group ranges are not set.",
				Target:  gardener.NewTarget("cluster", "shoot", "name", "shoot-psp", "kind", "podSecurityPolicy"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when all PSPs fail with supplemental group", func() {
		rule := &v1r8.Rule242437{
			Logger:                testLogger,
			ClusterClient:         fakeShootClient,
			ClusterVersion:        kubernetesVersion124,
			ControlPlaneClient:    fakeSeedClient,
			ControlPlaneVersion:   kubernetesVersion124,
			ControlPlaneNamespace: namespace,
		}
		seedPSP.Spec.SupplementalGroups.Ranges = []policyv1beta1.IDRange{
			{
				Min: 0,
			},
		}
		Expect(fakeSeedClient.Create(ctx, seedPSP)).To(Succeed())
		shootPSP.Spec.SupplementalGroups.Ranges = []policyv1beta1.IDRange{
			{
				Min: 1000,
			},
			{
				Min: 0,
			},
		}
		Expect(fakeShootClient.Create(ctx, shootPSP)).To(Succeed())

		ruleResult, err := rule.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []dikirule.CheckResult{
			{
				Status:  dikirule.Failed,
				Message: "Pod security policy supplemental group range not excluding 0.",
				Target:  gardener.NewTarget("cluster", "seed", "name", "seed-psp", "kind", "podSecurityPolicy"),
			},
			{
				Status:  dikirule.Failed,
				Message: "Pod security policy supplemental group range not excluding 0.",
				Target:  gardener.NewTarget("cluster", "shoot", "name", "shoot-psp", "kind", "podSecurityPolicy"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when all PSPs fail with RunAsUser", func() {
		rule := &v1r8.Rule242437{
			Logger:                testLogger,
			ClusterClient:         fakeShootClient,
			ClusterVersion:        kubernetesVersion124,
			ControlPlaneClient:    fakeSeedClient,
			ControlPlaneVersion:   kubernetesVersion124,
			ControlPlaneNamespace: namespace,
		}
		seedPSP.Spec.RunAsUser.Rule = "MustRunAs"
		Expect(fakeSeedClient.Create(ctx, seedPSP)).To(Succeed())
		shootPSP.Spec.RunAsUser.Rule = "RunAsAny"
		Expect(fakeShootClient.Create(ctx, shootPSP)).To(Succeed())

		ruleResult, err := rule.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []dikirule.CheckResult{
			{
				Status:  dikirule.Failed,
				Message: "Pod security policy run user not defined as MustRunAsNonRoot.",
				Target:  gardener.NewTarget("cluster", "seed", "name", "seed-psp", "kind", "podSecurityPolicy"),
			},
			{
				Status:  dikirule.Failed,
				Message: "Pod security policy run user not defined as MustRunAsNonRoot.",
				Target:  gardener.NewTarget("cluster", "shoot", "name", "shoot-psp", "kind", "podSecurityPolicy"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should return correct results when all PSPs fail with multiple reasons", func() {
		rule := &v1r8.Rule242437{
			Logger:                testLogger,
			ClusterClient:         fakeShootClient,
			ClusterVersion:        kubernetesVersion124,
			ControlPlaneClient:    fakeSeedClient,
			ControlPlaneVersion:   kubernetesVersion124,
			ControlPlaneNamespace: namespace,
		}
		seedPSP.Spec.FSGroup.Ranges = []policyv1beta1.IDRange{
			{
				Min: 0,
			},
		}
		seedPSP.Spec.RunAsUser.Rule = "MustRunAs"
		Expect(fakeSeedClient.Create(ctx, seedPSP)).To(Succeed())
		shootPSP.Spec.SupplementalGroups.Ranges = []policyv1beta1.IDRange{
			{
				Min: 0,
			},
		}
		shootPSP.Spec.RunAsUser.Rule = "RunAsAny"
		Expect(fakeShootClient.Create(ctx, shootPSP)).To(Succeed())

		ruleResult, err := rule.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []dikirule.CheckResult{
			{
				Status:  dikirule.Failed,
				Message: "Pod security policy fs group range not excluding 0.",
				Target:  gardener.NewTarget("cluster", "seed", "name", "seed-psp", "kind", "podSecurityPolicy"),
			},
			{
				Status:  dikirule.Failed,
				Message: "Pod security policy run user not defined as MustRunAsNonRoot.",
				Target:  gardener.NewTarget("cluster", "seed", "name", "seed-psp", "kind", "podSecurityPolicy"),
			},
			{
				Status:  dikirule.Failed,
				Message: "Pod security policy supplemental group range not excluding 0.",
				Target:  gardener.NewTarget("cluster", "shoot", "name", "shoot-psp", "kind", "podSecurityPolicy"),
			},
			{
				Status:  dikirule.Failed,
				Message: "Pod security policy run user not defined as MustRunAsNonRoot.",
				Target:  gardener.NewTarget("cluster", "shoot", "name", "shoot-psp", "kind", "podSecurityPolicy"),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})

	It("should skip rule when kubernetes version is >= v1.25.", func() {
		rule := &v1r8.Rule242437{
			Logger:                testLogger,
			ClusterClient:         fakeShootClient,
			ClusterVersion:        kubernetesVersion125,
			ControlPlaneClient:    fakeSeedClient,
			ControlPlaneVersion:   kubernetesVersion125,
			ControlPlaneNamespace: namespace,
		}

		ruleResult, err := rule.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		expectedCheckResults := []dikirule.CheckResult{
			{
				Status:  dikirule.Skipped,
				Message: "Pod security policies dropped with Kubernetes v1.25.",
				Target:  gardener.NewTarget("cluster", "seed", "details", "Cluster uses Kubernetes 1.25.0."),
			},
			{
				Status:  dikirule.Skipped,
				Message: "Pod security policies dropped with Kubernetes v1.25.",
				Target:  gardener.NewTarget("cluster", "shoot", "details", "Cluster uses Kubernetes 1.25.0."),
			},
		}

		Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
	})
})
