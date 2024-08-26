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

var _ = Describe("#242379", func() {
	const (
		ctsAutoTLSnotSetConfig = `
client-transport-security:`
		ctsAutoTLSsetFalseConfig = `
client-transport-security:
  auto-tls: false`
		ctsAutoTLSsetTrueConfig = `
client-transport-security:
  auto-tls: true`
	)

	var (
		fakeClient client.Client
		ctx        = context.TODO()
		namespace  = "foo"

		etcdMainStatefulSet   *appsv1.StatefulSet
		etcdEventsStatefulSet *appsv1.StatefulSet
		targetEtcdMain        = rule.NewTarget("name", "etcd-main", "namespace", namespace, "kind", "statefulSet")
		targetEtcdEvents      = rule.NewTarget("name", "etcd-events", "namespace", namespace, "kind", "statefulSet")
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		etcdMainStatefulSet = &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "etcd-main",
				Namespace: namespace,
			},
			Spec: appsv1.StatefulSetSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Volumes: []corev1.Volume{},
					},
				},
			},
		}
		etcdEventsStatefulSet = &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "etcd-events",
				Namespace: namespace,
			},
			Spec: appsv1.StatefulSetSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Volumes: []corev1.Volume{},
					},
				},
			},
		}
	})

	It("should return error check results when etcd-main and etcd-events are not found", func() {
		r := &rules.Rule242379{Client: fakeClient, Namespace: namespace}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			{
				Status:  rule.Errored,
				Message: "statefulsets.apps \"etcd-main\" not found",
				Target:  targetEtcdMain,
			},
			{
				Status:  rule.Errored,
				Message: "statefulsets.apps \"etcd-events\" not found",
				Target:  targetEtcdEvents,
			},
		},
		))
	})

	DescribeTable("Run cases",
		func(etcdMainVolume, etcdEventsVolume corev1.Volume, etcdMainSecret, etcdEventsSecret *corev1.Secret, expectedCheckResults []rule.CheckResult, errorMatcher gomegatypes.GomegaMatcher) {
			etcdMainStatefulSet.Spec.Template.Spec.Volumes = []corev1.Volume{etcdMainVolume}
			Expect(fakeClient.Create(ctx, etcdMainStatefulSet)).To(Succeed())

			etcdEventsStatefulSet.Spec.Template.Spec.Volumes = []corev1.Volume{etcdEventsVolume}
			Expect(fakeClient.Create(ctx, etcdEventsStatefulSet)).To(Succeed())

			Expect(fakeClient.Create(ctx, etcdMainSecret)).To(Succeed())
			Expect(fakeClient.Create(ctx, etcdEventsSecret)).To(Succeed())

			r := &rules.Rule242379{Client: fakeClient, Namespace: namespace}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should pass when client-transport-security.auto-tls is set to allowed value",
			corev1.Volume{Name: "etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "foo"}}},
			corev1.Volume{Name: "etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "bar"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(ctsAutoTLSnotSetConfig)}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bar", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(ctsAutoTLSsetFalseConfig)}},
			[]rule.CheckResult{
				{
					Status:  rule.Warning,
					Message: "Option client-transport-security.auto-tls has not been set.",
					Target:  targetEtcdMain,
				},
				{
					Status:  rule.Passed,
					Message: "Option client-transport-security.auto-tls set to allowed value.",
					Target:  targetEtcdEvents,
				},
			},
			BeNil()),
		Entry("should fail when client-transport-security.auto-tls is set to not allowed value",
			corev1.Volume{Name: "etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "foo"}}},
			corev1.Volume{Name: "etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "bar"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(ctsAutoTLSsetTrueConfig)}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bar", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(ctsAutoTLSsetTrueConfig)}},
			[]rule.CheckResult{
				{
					Status:  rule.Failed,
					Message: "Option client-transport-security.auto-tls set to not allowed value.",
					Target:  targetEtcdMain,
				},
				{
					Status:  rule.Failed,
					Message: "Option client-transport-security.auto-tls set to not allowed value.",
					Target:  targetEtcdEvents,
				},
			},
			BeNil()),
		Entry("should error when statefulSet does not have volume 'etcd-config-file' or secret is not found",
			corev1.Volume{Name: "not-etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "foo"}}},
			corev1.Volume{Name: "etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "bar"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(ctsAutoTLSsetTrueConfig)}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "not-bar", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(ctsAutoTLSsetTrueConfig)}},
			[]rule.CheckResult{
				{
					Status:  rule.Errored,
					Message: "StatefulSet does not contain volume with name: etcd-config-file.",
					Target:  targetEtcdMain,
				},
				{
					Status:  rule.Errored,
					Message: "secrets \"bar\" not found",
					Target:  targetEtcdEvents,
				},
			},
			BeNil()),
	)
})
