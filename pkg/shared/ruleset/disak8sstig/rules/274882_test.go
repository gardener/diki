// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
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

var _ = Describe("#274882", func() {

	var (
		fakeClient client.Client
		ctx        = context.TODO()
		namespace  = "foo"

		ksDeployment *appsv1.Deployment
		target       = rule.NewTarget("name", "kube-apiserver", "namespace", namespace, "kind", "Deployment")
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		ksDeployment = &appsv1.Deployment{
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
							},
						},
					},
				},
			},
		}
	})

	It("should error when kube-apiserver is not found", func() {
		r := &rules.Rule274882{Client: fakeClient, Namespace: namespace}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			{
				Status:  rule.Errored,
				Message: "deployments.apps \"kube-apiserver\" not found",
				Target:  target,
			},
		}))
	})

	DescribeTable("Run cases for encryption-provider-config flag",
		func(container corev1.Container, expectedCheckResults []rule.CheckResult, errorMatcher gomegatypes.GomegaMatcher) {
			ksDeployment.Spec.Template.Spec.Containers = []corev1.Container{container}
			Expect(fakeClient.Create(ctx, ksDeployment)).To(Succeed())

			r := &rules.Rule274882{Client: fakeClient, Namespace: namespace}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},
		Entry("should warn when encryption-provider-config is set more than once",
			corev1.Container{Name: "kube-apiserver", Command: []string{"--encryption-provider-config=/etc/kubernetes/foo", "--encryption-provider-config=/etc/kubernetes/foo"}},
			[]rule.CheckResult{{Status: rule.Warning, Message: "Option encryption-provider-config has been set more than once in the container command.", Target: target}},
			BeNil()),
		Entry("should error when deployment does not have container 'kube-apiserver'",
			corev1.Container{Name: "not-kube-apiserver", Command: []string{"--encryption-provider-config=/etc/kubernetes/foo"}},
			[]rule.CheckResult{{Status: rule.Errored, Message: "deployment: kube-apiserver does not contain container: kube-apiserver", Target: target}},
			BeNil()),
		Entry("should fail when encryption-provider-config is not set",
			corev1.Container{Name: "kube-apiserver", Command: []string{}},
			[]rule.CheckResult{{Status: rule.Failed, Message: "Option encryption-provider-config has not been set in the container command.", Target: target}},
			BeNil()),
	)

	DescribeTable("Run cases for an EncryptionConfiguration object",
		func(encryptionProviderConfig string, expectedCheckResult rule.CheckResult) {
			ksDeployment.Spec.Template.Spec.Containers = []corev1.Container{
				{
					Name:    "kube-apiserver",
					Command: []string{"./command"},
					Args:    []string{"--encryption-provider-config=/etc/kubernetes/foo"},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "encryption-provider-config",
							MountPath: "/etc/kubernetes/foo",
						},
					},
				},
			}

			ksDeployment.Spec.Template.Spec.Volumes = []corev1.Volume{
				{
					Name: "encryption-provider-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "encryption-provider-config",
							},
						},
					},
				},
			}
			Expect(fakeClient.Create(ctx, ksDeployment)).To(Succeed())

			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "encryption-provider-config",
					Namespace: namespace,
				},
				Data: map[string]string{
					"/etc/kubernetes/foo": encryptionProviderConfig,
				},
			}
			Expect(fakeClient.Create(ctx, configMap)).To(Succeed())

			r := &rules.Rule274882{Client: fakeClient, Namespace: namespace}
			ruleResult, err := r.Run(ctx)

			Expect(err).To(BeNil())
			Expect(ruleResult.CheckResults[0]).To(Equal(expectedCheckResult))
		},
		Entry("should error when the encryption config is not valid yaml",
			"foo",
			rule.CheckResult{Status: rule.Errored, Message: "yaml: construct errors:\n  line 1: cannot construct !!str `foo` into apiserver.EncryptionConfiguration", Target: target},
		),
		Entry("should fail when the encryption config has no resources configured",
			`
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration`,
			rule.CheckResult{Status: rule.Failed, Message: "Secrets are not explicitly encrypted at REST.", Target: target},
		),
		Entry("should fail when the encryption config does not include secrets as a resource for encryption",
			`
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - pods
  providers:
  - aesgcm:
      keys:
      - name: key1
        secret: c2VjcmV0IGlzIHNlY3VyZQ==`,
			rule.CheckResult{Status: rule.Failed, Message: "Secrets are not explicitly encrypted at REST.", Target: target},
		),
		Entry("should fail when the encryption config includes secrets as a resource but encrypts then with identity",
			`
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - identity: {}`,
			rule.CheckResult{Status: rule.Failed, Message: "Secrets are explicitly stored as plain text.", Target: target},
		),
		Entry("should fail when encryption config includes secrets as a resource and contains multiple providers but identity is the primary one",
			`
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - identity: {}
  - aesgcm:
      keys:
      - name: key1
        secret: c2VjcmV0IGlzIHNlY3VyZQ==`,
			rule.CheckResult{Status: rule.Failed, Message: "Secrets are explicitly stored as plain text.", Target: target},
		),
		Entry("should pass when encryption config includes secrets as a resource and contains multiple providers and a valid one is the primary one",
			`
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - aesgcm:
      keys:
      - name: key1
        secret: c2VjcmV0IGlzIHNlY3VyZQ==
  - identity: {}`,
			rule.CheckResult{Status: rule.Passed, Message: "Secrets are encrypted at REST.", Target: target}),
		Entry("should fail when encryption config includes a wildcard resource for secrets but identity is the primary provider",
			`
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - "*.*"
  providers:
  - identity: {}
  - aesgcm:
      keys:
      - name: key1
        secret: c2VjcmV0IGlzIHNlY3VyZQ==`,
			rule.CheckResult{Status: rule.Failed, Message: "Secrets are explicitly stored as plain text.", Target: target}),
		Entry("should pass when encryption configuration includes a wildcard resource for secrets and a valid primary provider",
			`
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - "*."
  providers:
  - aesgcm:
      keys:
      - name: key1
        secret: c2VjcmV0IGlzIHNlY3VyZQ==
  - identity: {}`,
			rule.CheckResult{Status: rule.Passed, Message: "Secrets are encrypted at REST.", Target: target},
		),
		Entry("should pass when there are multiple resource entries and secrets are properly encrypted in one of them",
			`
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - aesgcm:
      keys:
      - name: key1
        secret: c2VjcmV0IGlzIHNlY3VyZQ==
  - identity: {}
- resources:
  - "*"
  providers:
  - identity: {}`,
			rule.CheckResult{Status: rule.Passed, Message: "Secrets are encrypted at REST.", Target: target},
		),
		Entry("should fail when there are multiple resource entries and the order of precedence overwrites the secret encryption",
			`
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - "*."
  providers:
  - identity: {}
- resources:
  - secrets
  providers:
  - aesgcm:
      keys:
      - name: key1
        secret: c2VjcmV0IGlzIHNlY3VyZQ==
  - identity: {}`, rule.CheckResult{Status: rule.Failed, Message: "Secrets are explicitly stored as plain text.", Target: target},
		),
		Entry("should warn if an encryption resource has more than one providers set simultaneously",
			`
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - "*."
  providers:
  - identity: {}
    aesgcm:
      keys:
      - name: key1
        secret: c2VjcmV0IGlzIHNlY3VyZQ==
- resources:
  - secrets
  providers:
  - aesgcm:
      keys:
      - name: key1
        secret: c2VjcmV0IGlzIHNlY3VyZQ==
  - identity: {}`, rule.CheckResult{Status: rule.Warning, Message: "Multiple encryption providers are set for secrets encryption at REST.", Target: target},
		),
		Entry("should fail if an encryption resource has no providers set",
			`
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - "*."
  providers:
  - {}
- resources:
  - secrets
  providers:
  - aesgcm:
      keys:
      - name: key1
        secret: c2VjcmV0IGlzIHNlY3VyZQ==
  - identity: {}`, rule.CheckResult{Status: rule.Failed, Message: "No provider has been set for secrets encryption at REST.", Target: target},
		),
	)
})
