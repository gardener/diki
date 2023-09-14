// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/kubernetes/pod"
	fakepod "github.com/gardener/diki/pkg/kubernetes/pod/fake"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r10"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242394", func() {
	var (
		instanceID            = "1"
		fakeClusterPodContext pod.PodContext
		ctx                   = context.TODO()
		target                = gardener.NewTarget("cluster", "shoot")
	)

	DescribeTable("Run cases",
		func(executeReturnString [][]string, executeReturnError [][]error, expectedCheckResults []rule.CheckResult) {
			fakeClusterPodContext = fakepod.NewFakeSimplePodContext(executeReturnString, executeReturnError)
			r := &v1r10.Rule242394{
				Logger:            testLogger,
				InstanceID:        instanceID,
				ClusterPodContext: fakeClusterPodContext,
			}

			ruleResult, err := r.Run(ctx)
			Expect(err).To(BeNil())

			Expect(ruleResult.CheckResults).To(Equal(expectedCheckResults))
		},

		Entry("should return failed checkResult when port 22 is opened",
			[][]string{{"port used!"}},
			[][]error{{nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("SSH daemon started on port 22", target),
			}),
		Entry("should return passed checkResult when second execute errors with sshd is not found in systemctl",
			[][]string{{"", ""}},
			[][]error{{nil, errors.New(" foo NO such file or directory  ")}},
			[]rule.CheckResult{
				rule.PassedCheckResult("SSH daemon service not installed", target),
			}),
		Entry("should return failed checkResult when sshd is enabled in systemctl",
			[][]string{{"", "Alias"}},
			[][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.FailedCheckResult("SSH daemon enabled", target),
			}),
		Entry("should return passed checkResult in other cases",
			[][]string{{"", "foo"}},
			[][]error{{nil, nil}},
			[]rule.CheckResult{
				rule.PassedCheckResult("SSH daemon disabled (or could not be probed)", target),
			}),
		Entry("should return errored checkResult when first execute errors",
			[][]string{{""}},
			[][]error{{errors.New("foo")}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("foo", target),
			}),
		Entry("should return errored checkResult when second execute errors",
			[][]string{{"", "foo"}},
			[][]error{{nil, errors.New("bar")}},
			[]rule.CheckResult{
				rule.ErroredCheckResult("bar", target),
			}),
	)
})
