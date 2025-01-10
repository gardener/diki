// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/report"
	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("report", func() {
	Describe("Report", func() {
		var (
			reportTime     time.Time
			providerID     = "provider-foo"
			providerName   = "Provider Foo"
			rulesetID      = "ruleset-foo"
			rulesetName    = "Ruleset Foo"
			rulesetVersion = "v1"
			simpleReport   report.Report
		)
		BeforeEach(func() {
			reportTime = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.Local)
			simpleReport = report.Report{
				Time:        reportTime,
				DikiVersion: "1",
				MinStatus:   rule.Accepted,
				Providers: []report.Provider{
					{
						ID:   providerID,
						Name: providerName,
						Rulesets: []report.Ruleset{
							{
								ID:      rulesetID,
								Name:    rulesetName,
								Version: rulesetVersion,
								Rules: []report.Rule{
									{
										ID:       "1",
										Name:     "1",
										Severity: rule.SeverityHigh,
										Checks: []report.Check{
											{
												Status:  "Accepted",
												Message: "foo",
												Targets: []rule.Target{},
											},
											{
												Status:  "Failed",
												Message: "bar",
												Targets: []rule.Target{},
											},
											{
												Status:  "Skipped",
												Message: "baz",
												Targets: []rule.Target{},
											},
										},
									},
									{
										ID:       "2",
										Name:     "2",
										Severity: rule.SeverityLow,
										Checks: []report.Check{
											{
												Status:  "Accepted",
												Message: "foo",
												Targets: []rule.Target{},
											},
											{
												Status:  "Accepted",
												Message: "bar",
												Targets: []rule.Target{},
											},
										},
									},
									{
										ID:       "3",
										Name:     "3",
										Severity: rule.SeverityLow,
										Checks: []report.Check{
											{
												Status:  "Failed",
												Message: "foo",
												Targets: []rule.Target{},
											},
											{
												Status:  "Failed",
												Message: "bar",
												Targets: []rule.Target{},
											},
										},
									},
								},
							},
						},
					},
				},
			}
		})

		It("should correctly remove ruleset checks that are below the minStatus", func() {
			expectedReportResult := report.Report{
				Time:        reportTime,
				DikiVersion: "1",
				MinStatus:   rule.Failed,
				Providers: []report.Provider{
					{
						ID:   providerID,
						Name: providerName,
						Rulesets: []report.Ruleset{
							{
								ID:      rulesetID,
								Name:    rulesetName,
								Version: rulesetVersion,
								Rules: []report.Rule{
									{
										ID:       "1",
										Name:     "1",
										Severity: rule.SeverityHigh,
										Checks: []report.Check{
											{
												Status:  "Failed",
												Message: "bar",
												Targets: []rule.Target{},
											},
										},
									},
									{
										ID:       "2",
										Name:     "2",
										Severity: rule.SeverityLow,
										Checks:   []report.Check{},
									},
									{
										ID:       "3",
										Name:     "3",
										Severity: rule.SeverityLow,
										Checks: []report.Check{
											{
												Status:  "Failed",
												Message: "foo",
												Targets: []rule.Target{},
											},
											{
												Status:  "Failed",
												Message: "bar",
												Targets: []rule.Target{},
											},
										},
									},
								},
							},
						},
					},
				},
			}
			simpleReport.SetMinStatus(rule.Failed)
			Expect(simpleReport).To(Equal(expectedReportResult))
		})

		It("should not alter the report when the passed minStatus is not lower the report's minStatus", func() {
			expectedReport := simpleReport
			simpleReport.SetMinStatus(rule.Passed)
			Expect(simpleReport).To(Equal(expectedReport))
		})
	})

})
