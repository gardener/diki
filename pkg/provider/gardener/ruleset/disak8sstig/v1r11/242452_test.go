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

var _ = Describe("#242452", func() {
	const (
		rawKubeletCommand            = `--config=/var/lib/kubelet/config/kubelet`
		compliantKubeletFileStats    = `644 0 0 /var/lib/kubelet/config/kubelet`
		nonCompliantKubeletFileStats = `654 0 0 /var/lib/kubelet/config/kubelet`
	)
	var (
		instanceID            = "1"
		fakeClusterPodContext pod.PodContext
		ctx                   = context.TODO()
	)

	DescribeTable("Run cases",
		func(clusterExecuteReturnString [][]string, clusterExecuteReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(clusterExecuteReturnString, clusterExecuteReturnError)
			r := &v1r11.Rule242452{
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
			[][]error{{nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/config/kubelet, permissions: 644")),
			}),
		Entry("should return failed checkResult when file does not comply",
			[][]string{{rawKubeletCommand, nonCompliantKubeletFileStats}},
			[][]error{{nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/config/kubelet, permissions: 654, expectedPermissionsMax: 644")),
			}),
	)
})
