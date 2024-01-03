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

var _ = Describe("#242453", func() {
	const (
		rawKubeletCommand                 = `--config=/var/lib/kubelet/config/kubelet`
		compliantKubeletFileStats         = `644 0 0 /var/lib/kubelet/config/kubelet`
		nonCompliantKubeletFileStats      = `644 1000 2000 /var/lib/kubelet/config/kubelet`
		nonCompliantUserKubeletFileStats  = `644 1000 0 /var/lib/kubelet/config/kubelet`
		nonCompliantGroupKubeletFileStats = `644 0 1000 /var/lib/kubelet/config/kubelet`
	)
	var (
		instanceID            = "1"
		fakeClusterPodContext pod.PodContext
		ctx                   = context.TODO()
	)

	DescribeTable("Run cases",
		func(clusterExecuteReturnString [][]string, clusterExecuteReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(clusterExecuteReturnString, clusterExecuteReturnError)
			r := &v1r11.Rule242453{
				Logger:            testLogger,
				InstanceID:        instanceID,
				ClusterPodContext: fakeClusterPodContext,
			}

			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should return passed checkResult when file complies",
			[][]string{{rawKubeletCommand, compliantKubeletFileStats}},
			[][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/config/kubelet, ownerUser: 0, ownerGroup: 0")),
			}),
		Entry("should return failed checkResult when file user owner does not comply",
			[][]string{{rawKubeletCommand, nonCompliantUserKubeletFileStats}},
			[][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/config/kubelet, ownerUser: 1000, expectedOwnerUsers: [0]")),
			}),
		Entry("should return failed checkResult when file group owner does not comply",
			[][]string{{rawKubeletCommand, nonCompliantGroupKubeletFileStats}},
			[][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/config/kubelet, ownerGroup: 1000, expectedOwnerGroups: [0]")),
			}),
		Entry("should return failed checkResults when file user and group owner does not comply",
			[][]string{{rawKubeletCommand, nonCompliantKubeletFileStats}},
			[][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/config/kubelet, ownerUser: 1000, expectedOwnerUsers: [0]")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/config/kubelet, ownerGroup: 2000, expectedOwnerGroups: [0]")),
			}),
	)
})
