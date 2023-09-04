// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r8"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242449", func() {
	var (
		ctx = context.TODO()
	)

	It("should skip rules with correct message", func() {
		r := &v1r8.Rule242449{}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			{
				Status:  rule.Skipped,
				Message: `Rule implemented by "node-files" for correctness, consistency, deduplication, reliability, and performance reasons.`,
				Target:  gardener.NewTarget(),
			},
		},
		))
	})
})
