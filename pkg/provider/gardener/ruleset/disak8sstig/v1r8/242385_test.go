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

var _ = Describe("#242385", func() {
	var (
		ctx = context.TODO()
	)

	It("should skip rules with correct message", func() {
		r := &v1r8.Rule242385{}

		ruleResult, err := r.Run(ctx)
		Expect(err).ToNot(HaveOccurred())

		Expect(ruleResult.CheckResults).To(Equal([]rule.CheckResult{
			{
				Status:  rule.Skipped,
				Message: `The Kubernetes Controller Manager runs in a container which already has limited access to network interfaces. In addition ingress traffic to the Kubernetes Controller Manager is restricted via network policies, making an unintended exposure less likely.`,
				Target:  gardener.NewTarget(),
			},
		},
		))
	})
})
