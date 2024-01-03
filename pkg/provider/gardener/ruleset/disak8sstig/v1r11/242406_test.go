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

var _ = Describe("#242406", func() {
	const (
		kubeletServicePath                       = `/etc/systemd/system/kubelet.service`
		compliantKubeletServiceFileStats         = `644 0 0 /etc/systemd/system/kubelet.service`
		nonCompliantKubeletServiceFileStats      = `644 1000 2000 /etc/systemd/system/kubelet.service`
		nonCompliantUserKubeletServiceFileStats  = `644 1000 0 /etc/systemd/system/kubelet.service`
		nonCompliantGroupKubeletServiceFileStats = `644 0 1000 /etc/systemd/system/kubelet.service`
	)
	var (
		instanceID            = "1"
		fakeClusterPodContext pod.PodContext
		ctx                   = context.TODO()
	)

	BeforeEach(func() {
		v1r11.Generator = &FakeRandString{CurrentChar: 'a'}
	})

	DescribeTable("Run cases",
		func(clusterExecuteReturnString [][]string, clusterExecuteReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(clusterExecuteReturnString, clusterExecuteReturnError)
			r := &v1r11.Rule242406{
				Logger:            testLogger,
				InstanceID:        instanceID,
				ClusterPodContext: fakeClusterPodContext,
			}

			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should return passed checkResult when file complies",
			[][]string{{kubeletServicePath, compliantKubeletServiceFileStats}},
			[][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected owners", rule.NewTarget("cluster", "shoot", "details", "fileName: /etc/systemd/system/kubelet.service, ownerUser: 0, ownerGroup: 0")),
			}),
		Entry("should return failed checkResult when file user owner does not comply",
			[][]string{{kubeletServicePath, nonCompliantUserKubeletServiceFileStats}},
			[][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("cluster", "shoot", "details", "fileName: /etc/systemd/system/kubelet.service, ownerUser: 1000, expectedOwnerUsers: [0]")),
			}),
		Entry("should return failed checkResult when file group owner does not comply",
			[][]string{{kubeletServicePath, nonCompliantGroupKubeletServiceFileStats}},
			[][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("cluster", "shoot", "details", "fileName: /etc/systemd/system/kubelet.service, ownerGroup: 1000, expectedOwnerGroups: [0]")),
			}),
		Entry("should return failed checkResults when file user and group owner does not comply",
			[][]string{{kubeletServicePath, nonCompliantKubeletServiceFileStats}},
			[][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has unexpected owner user", rule.NewTarget("cluster", "shoot", "details", "fileName: /etc/systemd/system/kubelet.service, ownerUser: 1000, expectedOwnerUsers: [0]")),
				rule.FailedCheckResult("File has unexpected owner group", rule.NewTarget("cluster", "shoot", "details", "fileName: /etc/systemd/system/kubelet.service, ownerGroup: 2000, expectedOwnerGroups: [0]")),
			}),
	)
})
