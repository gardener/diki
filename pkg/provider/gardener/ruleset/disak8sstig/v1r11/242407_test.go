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

var _ = Describe("#242407", func() {
	const (
		kubeletServicePath                  = `/etc/systemd/system/kubelet.service`
		compliantKubeletServiceFileStats    = `644 0 0 /etc/systemd/system/kubelet.service`
		nonCompliantKubeletServiceFileStats = `700 0 0 /etc/systemd/system/kubelet.service`
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
			r := &v1r11.Rule242407{
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
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "shoot", "details", "fileName: /etc/systemd/system/kubelet.service, permissions: 644")),
			}),
		Entry("should return failed checkResults when file does not comply",
			[][]string{{kubeletServicePath, nonCompliantKubeletServiceFileStats}},
			[][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "shoot", "details", "fileName: /etc/systemd/system/kubelet.service, permissions: 700, expectedPermissionsMax: 644")),
			}),
	)
})
