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

var _ = Describe("#245543", func() {

	const (
		notValidEntry   = `foo,bar`
		acceptedEntry   = `foo,health-check,health-check`
		acceptedEntries = `foo,health-check,health-check
bar,root,0,group`
		acceptedEntryGroups = `foo,groups,groups,"group1,group2,group3"`
		notAcceptedEntry    = `foo,foo,bar`
		notAcceptedEntries  = `foo,health-check,health-check
bar,for,bar,`
	)

	var (
		fakeClient client.Client
		ctx        = context.TODO()
		namespace  = "foo"

		kapiDeployment *appsv1.Deployment
		target         = gardener.NewTarget("cluster", "seed", "kind", "deployment", "name", "kube-apiserver", "namespace", namespace)
		options        = v1r8.Options245543{
			AcceptedTokens: []struct {
				User   string `yaml:"user"`
				Uid    string `yaml:"uid"`
				Groups string `yaml:"groups"`
			}{
				{
					User: "health-check",
					Uid:  "health-check",
				},
				{
					User:   "root",
					Uid:    "0",
					Groups: "group",
				},
				{
					User:   "groups",
					Uid:    "groups",
					Groups: "group1,group2,group3",
				},
			},
		}
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
						Containers: []corev1.Container{
							{
								Name:    "kube-apiserver",
								Command: []string{},
								Args:    []string{},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "static-token",
										MountPath: "foo/bar",
									},
								},
							},
						},
						Volumes: []corev1.Volume{},
					},
				},
			},
		}
	})

	It("should return error check results when kube-apiserver is not found", func() {
		rule := &v1r8.Rule245543{Logger: testLogger, Client: fakeClient, Namespace: namespace}

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
		func(command []string, options *v1r8.Options245543, kapiVolume corev1.Volume, staticTokenSecret *corev1.Secret, expectedCheckResults []dikirule.CheckResult, errorMatcher gomegatypes.GomegaMatcher) {
			kapiDeployment.Spec.Template.Spec.Containers[0].Command = command
			kapiDeployment.Spec.Template.Spec.Volumes = []corev1.Volume{kapiVolume}
			Expect(fakeClient.Create(ctx, kapiDeployment)).To(Succeed())

			Expect(fakeClient.Create(ctx, staticTokenSecret)).To(Succeed())

			rule := &v1r8.Rule245543{Logger: testLogger, Client: fakeClient, Namespace: namespace, Options: options}
			ruleResult, err := rule.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should pass when token-auth-file is not set",
			[]string{"--not-token-auth-file"}, nil,
			corev1.Volume{Name: "static-token"},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Passed,
					Message: "Option token-auth-file has not been set.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should fail when token-auth-file is set",
			[]string{"--token-auth-file=foo/bar"}, nil,
			corev1.Volume{Name: "static-token"},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Failed,
					Message: "Option token-auth-file is set.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should warn when token-auth-file is set more than once and options are used.",
			[]string{"--token-auth-file=foo/bar", "--token-auth-file=foobar"}, &options,
			corev1.Volume{Name: "static-token"},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Warning,
					Message: "Option token-auth-file has been set more than once in container command.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should accept when token has been accepted.",
			[]string{"--token-auth-file=foo/bar/static_tokens.csv"}, &options,
			corev1.Volume{Name: "static-token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "foo"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string][]byte{"static_tokens.csv": []byte(acceptedEntry)}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Accepted,
					Message: "All defined tokens are accepted.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should accept when there are more than 1 accepted tokens.",
			[]string{"--token-auth-file=foo/bar/static_tokens.csv"}, &options,
			corev1.Volume{Name: "static-token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "foo"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string][]byte{"static_tokens.csv": []byte(acceptedEntries)}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Accepted,
					Message: "All defined tokens are accepted.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should accept when token has been accepted and has more than 1 group.",
			[]string{"--token-auth-file=foo/bar/static_tokens.csv"}, &options,
			corev1.Volume{Name: "static-token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "foo"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string][]byte{"static_tokens.csv": []byte(acceptedEntryGroups)}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Accepted,
					Message: "All defined tokens are accepted.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should fail when token is not accepted.",
			[]string{"--token-auth-file=foo/bar/static_tokens.csv"}, &options,
			corev1.Volume{Name: "static-token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "foo"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string][]byte{"static_tokens.csv": []byte(notAcceptedEntry)}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Failed,
					Message: "Invalid token.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should fail when there are mor tha 1 tokens and at least 1 is not accepted.",
			[]string{"--token-auth-file=foo/bar/static_tokens.csv"}, &options,
			corev1.Volume{Name: "static-token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "foo"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string][]byte{"static_tokens.csv": []byte(notAcceptedEntries)}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Failed,
					Message: "Invalid token.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should fail when not valid token is used.",
			[]string{"--token-auth-file=foo/bar/static_tokens.csv"}, &options,
			corev1.Volume{Name: "static-token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "foo"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string][]byte{"static_tokens.csv": []byte(notValidEntry)}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Failed,
					Message: "Invalid token.",
					Target:  target,
				},
			},
			BeNil()),
		Entry("should error when volume cannot be found.",
			[]string{"--token-auth-file=foobar/static_tokens.csv"}, &options,
			corev1.Volume{Name: "static-token"},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}},
			[]dikirule.CheckResult{
				{
					Status:  dikirule.Errored,
					Message: "cannot find volume with path foobar/static_tokens.csv",
					Target:  target,
				},
			},
			BeNil()),
	)
})
