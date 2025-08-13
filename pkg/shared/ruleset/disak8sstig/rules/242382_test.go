// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

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

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ = Describe("#242382", func() {
	const (
		authzConfig = `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
- type: Node
  name: node
- type: RBAC
  name: rbac
- type: Webhook
  name: Webhook`
		notAllowedAuthzConfig = `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
- type: AlwaysAllow
  name: AlwaysAllow`
		notExpectedAuthzConfig = `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
- type: Webhook
  name: Webhook
- type: Node
  name: node
- type: RBAC
  name: rbac`
		notAllExpectedAuthzConfig = `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
- type: Node
  name: node`
		wrongOrderAuthzConfig = `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
- type: RBAC
  name: rbac
- type: Node
  name: node`
	)
	var (
		fakeClient                client.Client
		ctx                       = context.TODO()
		namespace                 = "foo"
		fileName                  = "fileName.yaml"
		configMapName             = "kube-apiserver-authorization-config"
		configMapData             = "configMapData"
		kcmDeployment             *appsv1.Deployment
		configMap                 *corev1.ConfigMap
		target                    = rule.NewTarget("name", "kube-apiserver", "namespace", namespace, "kind", "Deployment")
		authorizationConfigTarget = rule.NewTarget("kind", "AuthorizationConfiguration")
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		kcmDeployment = &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-apiserver",
				Namespace: namespace,
			},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:    "kube-apiserver",
								Command: []string{},
								Args:    []string{},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "authorization-config",
										MountPath: "/foo/bar",
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "authorization-config",
								VolumeSource: corev1.VolumeSource{
									ConfigMap: &corev1.ConfigMapVolumeSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: configMapName,
										},
									},
								},
							},
						},
					},
				},
			},
		}
		configMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      configMapName,
				Namespace: namespace,
			},
			Data: map[string]string{
				fileName: configMapData,
			},
		}
	})

	It("should error when kube-apiserver is not found", func() {
		r := &rules.Rule242382{Client: fakeClient, Namespace: namespace}
		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			{
				Status:  rule.Errored,
				Message: "deployments.apps \"kube-apiserver\" not found",
				Target:  target,
			},
		},
		))
	})

	DescribeTable("Run authorization-mode cases",
		func(expectedModes []string, container corev1.Container, expectedCheckResults []rule.CheckResult, errorMatcher gomegatypes.GomegaMatcher) {
			kcmDeployment.Spec.Template.Spec.Containers = []corev1.Container{container}
			Expect(fakeClient.Create(ctx, kcmDeployment)).To(Succeed())

			r := &rules.Rule242382{
				Client:             fakeClient,
				Namespace:          namespace,
				ExpectedStartModes: expectedModes,
			}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should fail when authorization-mode is not set", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--flag1=value1", "--flag2=value2"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option authorization-mode has not been set.", Target: target}},
			BeNil()),
		Entry("should pass when authorization-mode is set to expected value Node,RBAC", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=Node,RBAC,Webhook"}},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Option authorization-mode set to expected value.", Target: target}},
			BeNil()),
		Entry("should fail when authorization-mode is set to not expected value RBAC,Node", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=RBAC,Node"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option authorization-mode set to not expected value.", Target: target}},
			BeNil()),
		Entry("should fail when authorization-mode is set to not allowed value AlwaysAllow", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=AlwaysAllow"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option authorization-mode set to not allowed value.", Target: target}},
			BeNil()),
		Entry("should fail when authorization-mode is set to not allowed value RBAC,Node,AlwaysAllow", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=RBAC,Node,AlwaysAllow"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option authorization-mode set to not allowed value.", Target: target}},
			BeNil()),
		Entry("should fail when authorization-mode is set to not expected value Node", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=Node"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option authorization-mode set to not expected value.", Target: target}},
			BeNil()),
		Entry("should fail when authorization-mode is set to not expected value RBAC,Node,other", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=RBAC,Node,other"}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option authorization-mode set to not expected value.", Target: target}},
			BeNil()),
		Entry("should return correct checkResults when expectedModes are set", []string{"RBAC", "Webhook"},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=RBAC,Webhook"}},
			[]rule.CheckResult{{Status: rule.Passed, Message: "Option authorization-mode set to expected value.", Target: target}},
			BeNil()),
		Entry("should warn when authorization-mode is set more than once", []string{},
			corev1.Container{Name: "kube-apiserver", Command: []string{"--authorization-mode=RBAC,Node"}, Args: []string{"--authorization-mode=Node,RBAC"}},
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option authorization-mode has been set more than once in container command.", Target: target}},
			BeNil()),
		Entry("should error when deployment does not have container 'kube-apiserver'", []string{},
			corev1.Container{Name: "not-kube-apiserver", Command: []string{"--authorization-mode=RBAC,Node"}},
			[]rule.CheckResult{{Status: rule.Errored, Message: "deployment: kube-apiserver does not contain container: kube-apiserver", Target: target}},
			BeNil()),
	)

	DescribeTable("Run AuthorizationConfiguration cases",
		func(expectedModes, command, args []string, configMapData map[string]string, expectedCheckResults []rule.CheckResult, errorMatcher gomegatypes.GomegaMatcher) {
			kcmDeployment.Spec.Template.Spec.Containers[0].Command = command
			kcmDeployment.Spec.Template.Spec.Containers[0].Args = args
			Expect(fakeClient.Create(ctx, kcmDeployment)).To(Succeed())

			configMap.Data = configMapData
			Expect(fakeClient.Create(ctx, configMap)).To(Succeed())

			r := &rules.Rule242382{
				Client:             fakeClient,
				Namespace:          namespace,
				ExpectedStartModes: expectedModes,
			}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should pass when AuthorizationConfiguration contains only expected mode types Node,RBAC", []string{},
			[]string{"--authorization-config=/foo/bar/fileName.yaml"}, []string{},
			map[string]string{fileName: authzConfig},
			[]rule.CheckResult{{Status: rule.Passed, Message: "AuthorizationConfiguration has expected start mode types set.", Target: authorizationConfigTarget}},
			BeNil()),
		Entry("should fail when AuthorizationConfiguration contains not allowed mode type AlwaysAllow", []string{},
			[]string{"--authorization-config=/foo/bar/fileName.yaml"}, []string{},
			map[string]string{fileName: notAllowedAuthzConfig},
			[]rule.CheckResult{{Status: rule.Failed, Message: "AuthorizationConfiguration has not allowed mode type set.", Target: authorizationConfigTarget}},
			BeNil()),
		Entry("should fail when AuthorizationConfiguration contains not expected mode type", []string{},
			[]string{"--authorization-config=/foo/bar/fileName.yaml"}, []string{},
			map[string]string{fileName: notExpectedAuthzConfig},
			[]rule.CheckResult{{Status: rule.Failed, Message: "AuthorizationConfiguration does not have expected start mode types set.", Target: authorizationConfigTarget}},
			BeNil()),
		Entry("should fail when AuthorizationConfiguration does not contain all expected mode types", []string{},
			[]string{"--authorization-config=/foo/bar/fileName.yaml"}, []string{},
			map[string]string{fileName: notAllExpectedAuthzConfig},
			[]rule.CheckResult{{Status: rule.Failed, Message: "AuthorizationConfiguration does not have expected start mode types set.", Target: authorizationConfigTarget}},
			BeNil()),
		Entry("should fail when AuthorizationConfiguration sets expected mode types in wrong order", []string{},
			[]string{"--authorization-config=/foo/bar/fileName.yaml"}, []string{},
			map[string]string{fileName: wrongOrderAuthzConfig},
			[]rule.CheckResult{{Status: rule.Failed, Message: "AuthorizationConfiguration does not have expected start mode types set.", Target: authorizationConfigTarget}},
			BeNil()),
		Entry("should return correct checkResults when expectedModes are set", []string{"Webhook", "Node", "RBAC"},
			[]string{"--authorization-config=/foo/bar/fileName.yaml"}, []string{},
			map[string]string{fileName: notExpectedAuthzConfig},
			[]rule.CheckResult{{Status: rule.Passed, Message: "AuthorizationConfiguration has expected start mode types set.", Target: authorizationConfigTarget}},
			BeNil()),
		Entry("should warn when authorization-config is set more than once", []string{},
			[]string{"--authorization-config=/foo/bar"}, []string{"--authorization-config=/bar/foo"}, map[string]string{},
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option authorization-config has been set more than once in container command.", Target: target}},
			BeNil()),
	)
})
