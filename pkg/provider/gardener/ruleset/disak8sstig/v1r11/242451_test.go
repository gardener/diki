// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r11"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242451", func() {
	const (
		compliantPKIAllFilesStats = `755 0 0 /var/lib/kubelet/pki
600 0 0 /var/lib/kubelet/pki/key.key
644 0 0 /var/lib/kubelet/pki/crt.crt
600 0 0 /var/lib/kubelet/pki/kubelet-server-2023.pem`
		nonCompliantPKIAllFilesStats = `755 0 0 /var/lib/kubelet/pki
644 1000 0 /var/lib/kubelet/pki/key.key
664 0 1000 /var/lib/kubelet/pki/crt.crt
644 1000 2000 /var/lib/kubelet/pki/kubelet-server-2023.pem`
	)
	var (
		instanceID            = "1"
		fakeClusterPodContext pod.PodContext
		ctx                   = context.TODO()
	)

	DescribeTable("Run cases",
		func(clusterExecuteReturnString [][]string, clusterExecuteReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(clusterExecuteReturnString, clusterExecuteReturnError)
			r := &v1r11.Rule242451{
				Logger:            testLogger,
				InstanceID:        instanceID,
				ClusterPodContext: fakeClusterPodContext,
			}

			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should return passed checkResults when file complies",
			[][]string{{compliantPKIAllFilesStats}},
			[][]error{{nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki/key.key, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki/crt.crt, ownerUser: 0, ownerGroup: 0")),
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki/kubelet-server-2023.pem, ownerUser: 0, ownerGroup: 0")),
			}),
		Entry("should return failed checkResults when file user and group owner does not comply",
			[][]string{{nonCompliantPKIAllFilesStats}},
			[][]error{{nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki, ownerUser: 0, ownerGroup: 0")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki/key.key, ownerUser: 1000, expectedOwnerUsers: [0]")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki/crt.crt, ownerGroup: 1000, expectedOwnerGroups: [0]")),
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki/kubelet-server-2023.pem, ownerUser: 1000, expectedOwnerUsers: [0]")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/pki/kubelet-server-2023.pem, ownerGroup: 2000, expectedOwnerGroups: [0]")),
			}),
	)
})
