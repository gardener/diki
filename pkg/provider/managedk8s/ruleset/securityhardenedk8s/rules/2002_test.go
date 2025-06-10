// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var _ = Describe("#2002", func() {
	var (
		client            client.Client
		plainStorageClass *storagev1.StorageClass

		ctx = context.TODO()

		deleteReclaimPolicy    corev1.PersistentVolumeReclaimPolicy = "Delete"
		notDeleteReclaimPolicy corev1.PersistentVolumeReclaimPolicy = "NotDelete"
	)

	BeforeEach(func() {
		client = fakeclient.NewClientBuilder().Build()
		plainStorageClass = &storagev1.StorageClass{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
				Labels: map[string]string{
					"foo": "bar",
				},
			},
		}
	})

	DescribeTable("Run casees", func(updateFn func(), ruleOptions rules.Options2002, expectedCheckResults []rule.CheckResult) {
		updateFn()

		r := rules.Rule2002{Client: client, Options: &ruleOptions}
		res, err := r.Run(ctx)
		Expect(err).To(BeNil())
		Expect(res.CheckResults).To(Equal(expectedCheckResults))
	},
		Entry("should pass when no storage classes are present",
			func() {}, rules.Options2002{},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "The cluster does not have any StorageClasses.", Target: rule.NewTarget()},
			},
		),
		Entry("should fail when a storage class's reclaim policy is default",
			func() {
				Expect(client.Create(ctx, plainStorageClass)).To(Succeed())
			}, rules.Options2002{},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "StorageClass does not have a Delete ReclaimPolicy set.", Target: rule.NewTarget("kind", "storageClass", "name", "default")},
			},
		),
		Entry("should pass when a storage class's reclaim policy is explicitly set to delete",
			func() {
				plainStorageClass.ReclaimPolicy = ptr.To(deleteReclaimPolicy)
				Expect(client.Create(ctx, plainStorageClass)).To(Succeed())
			}, rules.Options2002{},
			[]rule.CheckResult{
				{Status: rule.Passed, Message: "StorageClass has a Delete ReclaimPolicy set.", Target: rule.NewTarget("kind", "storageClass", "name", "default")},
			},
		),
		Entry("should fail when a storage class's reclaim policy is set to a non-delete value",
			func() {
				plainStorageClass.ReclaimPolicy = ptr.To(notDeleteReclaimPolicy)
				Expect(client.Create(ctx, plainStorageClass)).To(Succeed())
			}, rules.Options2002{},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "StorageClass does not have a Delete ReclaimPolicy set.", Target: rule.NewTarget("kind", "storageClass", "name", "default")},
			},
		),
		Entry("should pass when a storage class's reclaim policy is set to a non-delete value but accepted by options",
			func() {
				plainStorageClass.ReclaimPolicy = ptr.To(notDeleteReclaimPolicy)
				Expect(client.Create(ctx, plainStorageClass)).To(Succeed())
			}, rules.Options2002{
				AcceptedStorageClasses: []option.AcceptedClusterObject{
					{
						ClusterObjectSelector: option.ClusterObjectSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
						Justification: "foo justify",
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Accepted, Message: "foo justify", Target: rule.NewTarget("kind", "storageClass", "name", "default")},
			},
		),
		Entry("should pass when a storage class's reclaim policy is set to a non-delete value but accepted by MatchLabels options",
			func() {
				plainStorageClass.ReclaimPolicy = ptr.To(notDeleteReclaimPolicy)
				Expect(client.Create(ctx, plainStorageClass)).To(Succeed())
			}, rules.Options2002{
				AcceptedStorageClasses: []option.AcceptedClusterObject{
					{
						ClusterObjectSelector: option.ClusterObjectSelector{
							MatchLabels: map[string]string{"foo": "bar"},
						},
						Justification: "foo justify",
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Accepted, Message: "foo justify", Target: rule.NewTarget("kind", "storageClass", "name", "default")},
			},
		),
		Entry("should return multiple check results when multiple storage classes are configured",
			func() {
				storageClassDefault := plainStorageClass.DeepCopy()
				storageClassDefault.Name = "storageClassDefault"
				Expect(client.Create(ctx, storageClassDefault)).To(Succeed())

				storageClassDeletePolicy := plainStorageClass.DeepCopy()
				storageClassDeletePolicy.Name = "storageClassDeletePolicyPolicy"
				storageClassDeletePolicy.ReclaimPolicy = ptr.To(deleteReclaimPolicy)
				Expect(client.Create(ctx, storageClassDeletePolicy)).To(Succeed())

				storageClassRetainPolicy := plainStorageClass.DeepCopy()
				storageClassRetainPolicy.Name = "storageClassRetainPolicyPolicy"
				storageClassRetainPolicy.ReclaimPolicy = ptr.To(notDeleteReclaimPolicy)
				storageClassRetainPolicy.Labels = map[string]string{"bar": "foo"}
				Expect(client.Create(ctx, storageClassRetainPolicy)).To(Succeed())
			}, rules.Options2002{
				AcceptedStorageClasses: []option.AcceptedClusterObject{
					{
						ClusterObjectSelector: option.ClusterObjectSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"bar": "foo"},
							},
						},
					},
				},
			},
			[]rule.CheckResult{
				{Status: rule.Failed, Message: "StorageClass does not have a Delete ReclaimPolicy set.", Target: rule.NewTarget("kind", "storageClass", "name", "storageClassDefault")},
				{Status: rule.Passed, Message: "StorageClass has a Delete ReclaimPolicy set.", Target: rule.NewTarget("kind", "storageClass", "name", "storageClassDeletePolicyPolicy")},
				{Status: rule.Accepted, Message: "StorageClass accepted to not have Delete ReclaimPolicy.", Target: rule.NewTarget("kind", "storageClass", "name", "storageClassRetainPolicyPolicy")},
			},
		),
	)
})
