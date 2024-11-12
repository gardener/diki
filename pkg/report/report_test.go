// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/report"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("report", func() {
	Describe("#Report", func() {
		DescribeTable("#CheckRuleTitles", func(rule report.Rule, expectedRuleTitle string) {
			Expect(report.CreateRuleTitle(rule.ID, rule.Severity, rule.Name)).To(Equal(expectedRuleTitle))
		},
			Entry("check rule title when severity is present", report.Rule{Name: "foo", ID: "1", Severity: rule.SeverityMedium}, "1 (Medium) - foo"),
			Entry("check rule title when severity is absent", report.Rule{Name: "foo", ID: "1"}, "1 - foo"),
		)
	})
})
