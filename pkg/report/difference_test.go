// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
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

var _ = Describe("diff", func() {
	Describe("#CreateDiff", func() {
		var (
			minStatus      rule.Status
			reportTime     time.Time
			providerID     = "provider-foo"
			providerName   = "Provider Foo"
			rulesetID      = "ruleset-foo"
			rulesetName    = "Ruleset Foo"
			rulesetVersion = "v1"
			simpleReport1  report.Report
			simpleReport2  report.Report
		)
		BeforeEach(func() {
			minStatus = rule.Passed
			reportTime = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.Local)
			simpleReport1 = report.Report{
				Time:      reportTime,
				MinStatus: minStatus,
				Providers: []report.Provider{
					{
						ID:   providerID,
						Name: providerName,
						Metadata: map[string]string{
							"id":  "foo",
							"bar": "foo",
						},
						Rulesets: []report.Ruleset{
							{
								ID:      rulesetID,
								Name:    rulesetName,
								Version: rulesetVersion,
								Rules: []report.Rule{
									{
										ID:   "1",
										Name: "1",
										Checks: []report.Check{
											{
												Status:  rule.Passed,
												Message: "foo",
												Targets: []rule.Target{},
											},
										},
									},
									{
										ID:   "2",
										Name: "2",
										Checks: []report.Check{
											{
												Status:  rule.Passed,
												Message: "foo",
												Targets: []rule.Target{},
											},
											{
												Status:  rule.Failed,
												Message: "foo",
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
			simpleReport2 = report.Report{
				Time:      reportTime,
				MinStatus: minStatus,
				Providers: []report.Provider{
					{
						ID:   providerID,
						Name: providerName,
						Metadata: map[string]string{
							"id":  "bar",
							"foo": "bar",
						},
						Rulesets: []report.Ruleset{
							{
								ID:      rulesetID,
								Name:    rulesetName,
								Version: rulesetVersion,
								Rules: []report.Rule{
									{
										ID:   "2",
										Name: "2",
										Checks: []report.Check{
											{
												Status:  rule.Passed,
												Message: "foo",
												Targets: []rule.Target{},
											},
										},
									},
									{
										ID:   "3",
										Name: "3",
										Checks: []report.Check{
											{
												Status:  rule.Passed,
												Message: "foo",
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
		It("should return error when reports do not have equal minStatus", func() {
			simpleReport2.MinStatus = rule.Failed

			diff, err := report.CreateDifference(simpleReport1, simpleReport2)

			Expect(diff).To(BeNil())
			Expect(err).To(MatchError("reports must have equal minStatus"))
		})
		It("should create correct diff", func() {
			simpleReport2.MinStatus = ""
			diff, err := report.CreateDifference(simpleReport1, simpleReport2)

			expectedDiff := &report.Difference{
				Time:      diff.Time,
				MinStatus: rule.Passed,
				Providers: []report.ProviderDifference{
					{
						ID:   "provider-foo",
						Name: "Provider Foo",
						OldMetadata: map[string]string{
							"id":   "foo",
							"bar":  "foo",
							"time": reportTime.Format(time.RFC3339),
						},
						NewMetadata: map[string]string{
							"id":   "bar",
							"foo":  "bar",
							"time": reportTime.Format(time.RFC3339),
						},

						Rulesets: []report.RulesetDifference{
							{
								ID:      "ruleset-foo",
								Name:    "Ruleset Foo",
								Version: "v1",
								Rules: []report.RuleDifference{
									{
										ID:   "1",
										Name: "1",
										Removed: []report.Check{
											{
												Status:  "Passed",
												Message: "foo",
											},
										},
									},
									{
										ID:   "2",
										Name: "2",
										Removed: []report.Check{
											{
												Status:  "Failed",
												Message: "foo",
											},
										},
									},
									{
										ID:   "3",
										Name: "3",
										Added: []report.Check{
											{
												Status:  "Passed",
												Message: "foo",
											},
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(diff).To(Equal(expectedDiff))
			Expect(err).To(BeNil())
		})
		It("should create correct diff of 2 reports with more than 1 ruleset", func() {
			simpleReport1.MinStatus = ""
			simpleReport2.Providers[0].Rulesets = append(simpleReport2.Providers[0].Rulesets, simpleReport1.Providers[0].Rulesets[0])
			simpleReport2.Providers[0].Rulesets[1].ID = "ruleset-bar"
			simpleReport2.Providers[0].Rulesets[1].Name = "Ruleset Bar"

			diff, err := report.CreateDifference(simpleReport1, simpleReport2)

			expectedDiff := &report.Difference{
				Time:      diff.Time,
				MinStatus: rule.Passed,
				Providers: []report.ProviderDifference{
					{
						ID:   "provider-foo",
						Name: "Provider Foo",
						OldMetadata: map[string]string{
							"id":   "foo",
							"bar":  "foo",
							"time": reportTime.Format(time.RFC3339),
						},
						NewMetadata: map[string]string{
							"id":   "bar",
							"foo":  "bar",
							"time": reportTime.Format(time.RFC3339),
						},
						Rulesets: []report.RulesetDifference{
							{
								ID:      "ruleset-foo",
								Name:    "Ruleset Foo",
								Version: "v1",
								Rules: []report.RuleDifference{
									{
										ID:   "1",
										Name: "1",
										Removed: []report.Check{
											{
												Status:  "Passed",
												Message: "foo",
											},
										},
									},
									{
										ID:   "2",
										Name: "2",
										Removed: []report.Check{
											{
												Status:  "Failed",
												Message: "foo",
											},
										},
									},
									{
										ID:   "3",
										Name: "3",
										Added: []report.Check{
											{
												Status:  "Passed",
												Message: "foo",
											},
										},
									},
								},
							},
							{
								ID:      "ruleset-bar",
								Name:    "Ruleset Bar",
								Version: "v1",
								Rules: []report.RuleDifference{
									{
										ID:   "1",
										Name: "1",
										Added: []report.Check{
											{
												Status:  "Passed",
												Message: "foo",
											},
										},
									},
									{
										ID:   "2",
										Name: "2",
										Added: []report.Check{
											{
												Status:  "Passed",
												Message: "foo",
											},
											{
												Status:  "Failed",
												Message: "foo",
											},
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(diff).To(Equal(expectedDiff))
			Expect(err).To(BeNil())
		})
		It("should create correct diff of 2 reports with more than 1 provider", func() {
			simpleReport2.Providers = append(simpleReport2.Providers, report.Provider{
				ID:   "new-provider",
				Name: "New Provider",
				Metadata: map[string]string{
					"key": "value2",
				},
				Rulesets: simpleReport1.Providers[0].Rulesets,
			})

			diff, err := report.CreateDifference(simpleReport1, simpleReport2)

			expectedDiff := &report.Difference{
				Time:      diff.Time,
				MinStatus: rule.Passed,
				Providers: []report.ProviderDifference{
					{
						ID:   "provider-foo",
						Name: "Provider Foo",
						OldMetadata: map[string]string{
							"id":   "foo",
							"bar":  "foo",
							"time": reportTime.Format(time.RFC3339),
						},
						NewMetadata: map[string]string{
							"id":   "bar",
							"foo":  "bar",
							"time": reportTime.Format(time.RFC3339),
						},
						Rulesets: []report.RulesetDifference{
							{
								ID:      "ruleset-foo",
								Name:    "Ruleset Foo",
								Version: "v1",
								Rules: []report.RuleDifference{
									{
										ID:   "1",
										Name: "1",
										Removed: []report.Check{
											{
												Status:  "Passed",
												Message: "foo",
											},
										},
									},
									{
										ID:   "2",
										Name: "2",
										Removed: []report.Check{
											{
												Status:  "Failed",
												Message: "foo",
											},
										},
									},
									{
										ID:   "3",
										Name: "3",
										Added: []report.Check{
											{
												Status:  "Passed",
												Message: "foo",
											},
										},
									},
								},
							},
						},
					},
					{
						ID:   "new-provider",
						Name: "New Provider",
						OldMetadata: map[string]string{
							"time": reportTime.Format(time.RFC3339),
						},
						NewMetadata: map[string]string{
							"key":  "value2",
							"time": reportTime.Format(time.RFC3339),
						},
						Rulesets: []report.RulesetDifference{
							{
								ID:      "ruleset-foo",
								Name:    "Ruleset Foo",
								Version: "v1",
								Rules: []report.RuleDifference{
									{
										ID:   "1",
										Name: "1",
										Added: []report.Check{
											{
												Status:  "Passed",
												Message: "foo",
											},
										},
									},
									{
										ID:   "2",
										Name: "2",
										Added: []report.Check{
											{
												Status:  "Passed",
												Message: "foo",
											},
											{
												Status:  "Failed",
												Message: "foo",
											},
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(diff).To(Equal(expectedDiff))
			Expect(err).To(BeNil())
		})
	})
})
