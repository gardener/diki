// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r8"
	dikirule "github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242403", func() {

	const (
		allowedAuditPolicy = `apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse`
		notAllowedMultiRuleAuditPolicy = `apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
- level: Metadata`
		notAllowedSingleRuleAuditPolicy = `apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  users: ["system:kube-proxy"]
  verbs: ["watch"]`
		notAllowedRuleLevelAuditPolicy = `apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata`
	)

	var (
		fakeClient client.Client
		ctx        = context.TODO()
		namespace  = "foo"

		kapiDeployment *appsv1.Deployment
		target         = gardener.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-apiserver", "namespace", namespace)
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		kapiDeployment = &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-apiserver",
				Namespace: namespace,
			},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Volumes: []corev1.Volume{},
					},
				},
			},
		}
	})

	It("should return error check results when kube-apiserver is not found", func() {
		rule := &v1r8.Rule242403{Logger: testLogger, Client: fakeClient, Namespace: namespace}

		ruleResult, err := rule.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		Expect(ruleResult.CheckResults).To(Equal([]dikirule.CheckResult{
			{
				Status:  dikirule.Errored,
				Message: "deployments.apps \"kube-apiserver\" not found",
				Target:  target,
			},
		},
		))
	})

	DescribeTable("Run cases",
		func(kapiVolume corev1.Volume, auditPolicyConfigMap *corev1.ConfigMap, expectedCheckResults []dikirule.CheckResult, errorMatcher gomegatypes.GomegaMatcher) {
			kapiDeployment.Spec.Template.Spec.Volumes = []corev1.Volume{kapiVolume}
			Expect(fakeClient.Create(ctx, kapiDeployment)).To(Succeed())

			Expect(fakeClient.Create(ctx, auditPolicyConfigMap)).To(Succeed())

			rule := &v1r8.Rule242403{Logger: testLogger, Client: fakeClient, Namespace: namespace}
			ruleResult, err := rule.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should pass when audit policy file is conformant with required specification",
			corev1.Volume{Name: "audit-policy-config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "foo"}}}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string]string{"audit-policy.yaml": allowedAuditPolicy}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Passed,
					Message: "Audit log policy file is conformant with required specification.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should fail when multiple rules are present in the audit policy file",
			corev1.Volume{Name: "audit-policy-config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "foo"}}}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string]string{"audit-policy.yaml": notAllowedMultiRuleAuditPolicy}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Failed,
					Message: "Audit log policy file is not conformant with required specification.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should fail when audit policy file is not conformant with required specification",
			corev1.Volume{Name: "audit-policy-config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "foo"}}}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string]string{"audit-policy.yaml": notAllowedSingleRuleAuditPolicy}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Failed,
					Message: "Audit log policy file is not conformant with required specification.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should fail when audit policy file is wrong level",
			corev1.Volume{Name: "audit-policy-config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "foo"}}}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string]string{"audit-policy.yaml": notAllowedRuleLevelAuditPolicy}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Failed,
					Message: "Audit log policy file is not conformant with required specification.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should error when volume is not found",
			corev1.Volume{Name: "not-audit-policy-config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "foo"}}}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string]string{"audit-policy.yaml": allowedAuditPolicy}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Errored,
					Message: "Deployment does not contain volume with name: audit-policy-config.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should error when configMap is not found",
			corev1.Volume{Name: "audit-policy-config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "foo"}}}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "not-foo", Namespace: namespace}, Data: map[string]string{"audit-policy.yaml": allowedAuditPolicy}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Errored,
					Message: "configmaps \"foo\" not found",
					Target:  target,
				},
			},
			BeNil()),
	)
})
