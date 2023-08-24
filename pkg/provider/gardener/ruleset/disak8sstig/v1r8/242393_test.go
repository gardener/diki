// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r8"
	"github.com/gardener/diki/pkg/rule"
	dikirule "github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242393", func() {
	var (
		instanceID            = "1"
		fakeClusterPodContext pod.PodContext
		ctx                   = context.TODO()
	)

	DescribeTable("Run cases",
		func(executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []dikirule.CheckResult) {
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			rule := &v1r8.Rule242393{
				Logger:            testLogger,
				InstanceID:        instanceID,
				ClusterPodContext: fakeClusterPodContext,
			}

			ruleResult, err := rule.Run(ctx)
			Expect(err).To(BeNil())

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should return failed checkResult when port 22 is opened",
			[][]string{{"port used!"}},
			[][]error{{nil}},
			[]dikirule.CheckResult{
				rule.FailedCheckResult("SSH daemon started on port 22", gardener.NewTarget("cluster", "shoot")),
			}),
		Entry("should return passed checkResult when sshd is not found in systemctl",
			[][]string{{"", "foo NO such file or directory"}},
			[][]error{{nil, nil}},
			[]dikirule.CheckResult{
				rule.PassedCheckResult("SSH daemon service not installed", gardener.NewTarget("cluster", "shoot")),
			}),
		Entry("should return failed checkResult when sshd is active in systemctl",
			[][]string{{"", "Active"}},
			[][]error{{nil, nil}},
			[]dikirule.CheckResult{
				rule.FailedCheckResult("SSH daemon active", gardener.NewTarget("cluster", "shoot")),
			}),
		Entry("should return passed checkResult in other cases",
			[][]string{{"", "foo"}},
			[][]error{{nil, nil}},
			[]dikirule.CheckResult{
				rule.PassedCheckResult("SSH daemon inactive (or could not be probed)", gardener.NewTarget("cluster", "shoot")),
			}),
		Entry("should return errored checkResult when first execute errors",
			[][]string{{""}},
			[][]error{{errors.New("foo")}},
			[]dikirule.CheckResult{
				rule.ErroredCheckResult("foo", gardener.NewTarget("cluster", "shoot")),
			}),
		Entry("should return errored checkResult when second execute errors",
			[][]string{{"", "foo"}},
			[][]error{{nil, errors.New("bat")}},
			[]dikirule.CheckResult{
				rule.ErroredCheckResult("bat", gardener.NewTarget("cluster", "shoot")),
			}),
	)
})
