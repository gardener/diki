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
	dikirule "github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242445", func() {
	var (
		ctx = context.TODO()
	)

	It("should skip rules with correct message", func() {
		rule := &v1r8.Rule242445{}

		ruleResult, err := rule.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		Expect(ruleResult.CheckResults).To(Equal([]dikirule.CheckResult{
			{
				Status:  dikirule.Skipped,
				Message: `Gardener does not deploy any control plane component as systemd processes or static pod. It is deployed as regular pod under root:root, not readable by non-root users, which is checked by "pod-files" for correctness, consistency, deduplication, reliability, and performance reasons.`,
				Target:  gardener.NewTarget(),
			},
		},
		))
	})
})
