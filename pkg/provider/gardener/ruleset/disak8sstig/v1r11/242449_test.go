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

var _ = Describe("#242449", func() {
	const (
		rawKubeletCommand = `--config=/var/lib/kubelet/config/kubelet`
		kubeletConfig     = `authentication:
  x509:
    clientCAFile: /var/lib/kubelet/ca.crt
`
		notSetClientCAFileConfig = `authentication:
  webhook:
    enabled: true
`
		compliantCAFileStats    = `644 0 0 /var/lib/kubelet/ca.crt`
		nonCompliantCAFileStats = `700 0 0 /var/lib/kubelet/ca.crt`
	)
	var (
		instanceID            = "1"
		fakeClusterPodContext pod.PodContext
		dikiPodName           = "diki-242449-aaaaaaaaaa"
		ctx                   = context.TODO()
	)

	BeforeEach(func() {
		v1r11.Generator = &FakeRandString{CurrentChar: 'a'}
	})

	DescribeTable("Run cases",
		func(clusterExecuteReturnString [][]string, clusterExecuteReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(clusterExecuteReturnString, clusterExecuteReturnError)
			r := &v1r11.Rule242449{
				Logger:            testLogger,
				InstanceID:        instanceID,
				ClusterPodContext: fakeClusterPodContext,
			}

			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should return passed checkResult when file complies",
			[][]string{{rawKubeletCommand, kubeletConfig, compliantCAFileStats}},
			[][]error{{nil, nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("File has expected permissions", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/ca.crt, permissions: 644")),
			}),
		Entry("should return failed checkResults when file does not comply",
			[][]string{{rawKubeletCommand, kubeletConfig, nonCompliantCAFileStats}},
			[][]error{{nil, nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("File has too wide permissions", rule.NewTarget("cluster", "shoot", "details", "fileName: /var/lib/kubelet/ca.crt, permissions: 700, expectedPermissionsMax: 644")),
			}),
		Entry("should return failed checkResults when clientCAFile is not set",
			[][]string{{rawKubeletCommand, notSetClientCAFileConfig}},
			[][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("could not find client ca path: client-ca-file not set.", rule.NewTarget("cluster", "shoot", "name", dikiPodName, "namespace", "kube-system", "kind", "pod")),
			}),
	)
})
