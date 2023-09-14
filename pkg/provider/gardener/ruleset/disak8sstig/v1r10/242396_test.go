// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig/v1r10"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("#242396", func() {
	var (
		ctx = context.TODO()
	)

	It("should skip rules with correct message", func() {
		r := &v1r10.Rule242396{}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			{
				Status:  rule.Skipped,
				Message: `"kubectl" is not installed into control plane pods or worker nodes and Gardener does not offer Kubernetes v1.12 or older.`,
				Target:  gardener.NewTarget(),
			},
		},
		))
	})
})
