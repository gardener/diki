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
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242426", func() {
	const (
		singleETCDCluster = `
initial-cluster: etcd-main-0=foo
peer-transport-security:
  client-cert-auth: false`
		ptsCertAuthNotSetConfig = `
initial-cluster: etcd-main-0=foo,etcd-main-1=bar
peer-transport-security:`
		ptsCertAuthSetFalseConfig = `
initial-cluster: etcd-main-0=foo,etcd-main-1=bar
peer-transport-security:
  client-cert-auth: false`
		ptsCertAuthSetTrueConfig = `
initial-cluster: etcd-main-0=foo,etcd-main-1=bar
peer-transport-security:
  client-cert-auth: true`
	)

	var (
		fakeClient client.Client
		ctx        = context.TODO()
		namespace  = "foo"

		etcdMainStatefulSet   *appsv1.StatefulSet
		etcdEventsStatefulSet *appsv1.StatefulSet
		targetEtcdMain        = gardener.NewTarget("cluster", "seed", "name", "etcd-main", "namespace", namespace, "kind", "statefulSet")
		targetEtcdEvents      = gardener.NewTarget("cluster", "seed", "name", "etcd-events", "namespace", namespace, "kind", "statefulSet")
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
		r := &v1r8.Rule242426{Logger: testLogger, Client: fakeClient, Namespace: namespace}

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

			r := &v1r8.Rule242426{Logger: testLogger, Client: fakeClient, Namespace: namespace}
			ruleResult, err := r.Run(ctx)
			Expect(err).To(errorMatcher)

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should pass when peer-transport-security.client-cert-auth is set to allowed value",
			corev1.Volume{Name: "etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "foo"}}},
			corev1.Volume{Name: "etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "bar"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(ptsCertAuthNotSetConfig)}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bar", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(ptsCertAuthSetTrueConfig)}},
			[]rule.CheckResult{
				{
					Status:  rule.Warning,
					Message: "Option peer-transport-security.client-cert-auth has not been set.",
					Target:  targetEtcdMain,
				},
				{
					Status:  rule.Passed,
					Message: "Option peer-transport-security.client-cert-auth set to allowed value.",
					Target:  targetEtcdEvents,
				},
			},
			BeNil()),
		Entry("should fail when peer-transport-security.client-cert-auth is set to not allowed value",
			corev1.Volume{Name: "etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "foo"}}},
			corev1.Volume{Name: "etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "bar"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(ptsCertAuthSetFalseConfig)}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bar", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(ptsCertAuthSetFalseConfig)}},
			[]rule.CheckResult{
				{
					Status:  rule.Failed,
					Message: "Option peer-transport-security.client-cert-auth set to not allowed value.",
					Target:  targetEtcdMain,
				},
				{
					Status:  rule.Failed,
					Message: "Option peer-transport-security.client-cert-auth set to not allowed value.",
					Target:  targetEtcdEvents,
				},
			},
			BeNil()),
		Entry("should error when statefulSet does not have volume 'etcd-config-file' or secret is not found",
			corev1.Volume{Name: "not-etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "foo"}}},
			corev1.Volume{Name: "etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "bar"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(ptsCertAuthSetTrueConfig)}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "not-bar", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(ptsCertAuthSetTrueConfig)}},
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
		Entry("should skip when initial-cluster is set with signel value",
			corev1.Volume{Name: "etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "foo"}}},
			corev1.Volume{Name: "etcd-config-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "bar"}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(singleETCDCluster)}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bar", Namespace: namespace}, Data: map[string][]byte{"etcd.conf.yaml": []byte(singleETCDCluster)}},
			[]rule.CheckResult{
				{
					Status:  rule.Skipped,
					Message: "ETCD runs as a single instance, peer communication options are not used.",
					Target:  targetEtcdMain,
				},
				{
					Status:  rule.Skipped,
					Message: "ETCD runs as a single instance, peer communication options are not used.",
					Target:  targetEtcdEvents,
				},
			},
			BeNil()),
	)
})
