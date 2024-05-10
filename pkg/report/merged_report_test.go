// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
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

var _ = Describe("merged report", func() {
	Describe("#MergeReport", func() {
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
				Time:        reportTime,
				MinStatus:   minStatus,
				DikiVersion: "1",
				Metadata: map[string]any{
					"foo": "bar",
				},
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
				Time:        reportTime,
				MinStatus:   minStatus,
				DikiVersion: "1",
				Metadata: map[string]any{
					"foo": "bar",
				},
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

		It("should return error when zero reports are provided for merging", func() {
			mergedReport, err := report.MergeReport([]*report.Report{}, map[string]string{providerID: "id"})

			Expect(mergedReport).To(BeNil())
			Expect(err).To(MatchError("zero reports provided for merging"))
		})

		It("should return error when reports do not have equal minStatus", func() {
			simpleReport2.MinStatus = rule.Failed
			reports := []*report.Report{&simpleReport1, &simpleReport2}
			mergedReport, err := report.MergeReport(reports, map[string]string{providerID: "id"})

			Expect(mergedReport).To(BeNil())
			Expect(err).To(MatchError("reports must have equal minStatus in order to be merged"))
		})

		It("should return error when at least 1 report does not contain the selected provider", func() {
			simpleReport2.Providers[0].ID = "not-provider-foo"
			reports := []*report.Report{&simpleReport1, &simpleReport2}
			mergedReport, err := report.MergeReport(reports, map[string]string{providerID: "id"})

			Expect(mergedReport).To(BeNil())
			Expect(err).To(MatchError("provider provider-foo not found in at least 1 of the selected reports"))
		})

		It("should return error when at distinct attribute is missing from at least 1 provider run", func() {
			delete(simpleReport2.Providers[0].Metadata, "id")
			reports := []*report.Report{&simpleReport1, &simpleReport2}
			mergedReport, err := report.MergeReport(reports, map[string]string{providerID: "id"})

			Expect(mergedReport).To(BeNil())
			Expect(err).To(MatchError("distinct attribute id is empty in at least 1 of the selected reports"))
		})

		It("should return error when at distinct attribute is not unique", func() {
			simpleReport2.Providers[0].Metadata["id"] = "foo"
			reports := []*report.Report{&simpleReport1, &simpleReport2}
			mergedReport, err := report.MergeReport(reports, map[string]string{providerID: "id"})

			Expect(mergedReport).To(BeNil())
			Expect(err).To(MatchError("distinct attribute id is not unique"))
		})

		It("should correctly merge 2 reports", func() {
			reports := []*report.Report{&simpleReport1, &simpleReport2}
			mergedReport, err := report.MergeReport(reports, map[string]string{providerID: "id"})

			expectedMergedReport := &report.MergedReport{
				Time:        mergedReport.Time,
				MinStatus:   rule.Passed,
				DikiVersion: "1",
				Metadata: map[string]any{
					"foo": "bar",
				},
				Providers: []report.MergedProvider{
					{
						ID:         "provider-foo",
						Name:       "Provider Foo",
						DistinctBy: "id",
						Metadata: map[string]map[string]string{
							"foo": {
								"id":   "foo",
								"bar":  "foo",
								"time": "01-01-2000 00:00:00",
							},
							"bar": {
								"id":   "bar",
								"foo":  "bar",
								"time": "01-01-2000 00:00:00",
							},
						},
						Rulesets: []report.MergedRuleset{
							{
								ID:      "ruleset-foo",
								Name:    "Ruleset Foo",
								Version: "v1",
								Rules: []report.MergedRule{
									{
										ID:   "1",
										Name: "1",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
												},
											},
										},
									},
									{
										ID:   "2",
										Name: "2",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
													"bar": {},
												},
											},
											{
												Status:  "Failed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
												},
											},
										},
									},
									{
										ID:   "3",
										Name: "3",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"bar": {},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(mergedReport).To(Equal(expectedMergedReport))
			Expect(err).To(BeNil())
		})

		It("should correctly merge 2 reports with differenct rulesets", func() {
			simpleReport2.Providers[0].Rulesets[0].ID = "ruleset-bar"
			simpleReport2.Providers[0].Rulesets[0].Name = "Ruleset Bar"
			reports := []*report.Report{&simpleReport1, &simpleReport2}
			mergedReport, err := report.MergeReport(reports, map[string]string{providerID: "id"})

			expectedMergedReport := &report.MergedReport{
				Time:        mergedReport.Time,
				MinStatus:   rule.Passed,
				DikiVersion: "1",
				Metadata: map[string]any{
					"foo": "bar",
				},
				Providers: []report.MergedProvider{
					{
						ID:         "provider-foo",
						Name:       "Provider Foo",
						DistinctBy: "id",
						Metadata: map[string]map[string]string{
							"foo": {
								"id":   "foo",
								"bar":  "foo",
								"time": "01-01-2000 00:00:00",
							},
							"bar": {
								"id":   "bar",
								"foo":  "bar",
								"time": "01-01-2000 00:00:00",
							},
						},
						Rulesets: []report.MergedRuleset{
							{
								ID:      "ruleset-foo",
								Name:    "Ruleset Foo",
								Version: "v1",
								Rules: []report.MergedRule{
									{
										ID:   "1",
										Name: "1",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
												},
											},
										},
									},
									{
										ID:   "2",
										Name: "2",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
												},
											},
											{
												Status:  "Failed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
												},
											},
										},
									},
								},
							},
							{
								ID:      "ruleset-bar",
								Name:    "Ruleset Bar",
								Version: "v1",
								Rules: []report.MergedRule{
									{
										ID:   "2",
										Name: "2",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"bar": {},
												},
											},
										},
									},
									{
										ID:   "3",
										Name: "3",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"bar": {},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(mergedReport).To(Equal(expectedMergedReport))
			Expect(err).To(BeNil())
		})

		It("should correctly merge 2 reports on more than 1 provider", func() {
			newProviderReport1 := report.Provider{
				ID:   "new-provider",
				Name: "New Provider",
				Metadata: map[string]string{
					"key": "value1",
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
						},
					},
				},
			}
			simpleReport1.Providers = append(simpleReport1.Providers, newProviderReport1)

			newProviderReport2 := report.Provider{
				ID:   "new-provider",
				Name: "New Provider",
				Metadata: map[string]string{
					"key": "value2",
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
						},
					},
				},
			}
			simpleReport2.Providers = append(simpleReport2.Providers, newProviderReport2)
			reports := []*report.Report{&simpleReport1, &simpleReport2}
			mergedReport, err := report.MergeReport(reports, map[string]string{providerID: "id", "new-provider": "key"})

			expectedMergedReport := &report.MergedReport{
				Time:        mergedReport.Time,
				MinStatus:   rule.Passed,
				DikiVersion: "1",
				Metadata: map[string]any{
					"foo": "bar",
				},
				Providers: []report.MergedProvider{
					{
						ID:         "new-provider",
						Name:       "New Provider",
						DistinctBy: "key",
						Metadata: map[string]map[string]string{
							"value1": {
								"key":  "value1",
								"time": "01-01-2000 00:00:00",
							},
							"value2": {
								"key":  "value2",
								"time": "01-01-2000 00:00:00",
							},
						},
						Rulesets: []report.MergedRuleset{
							{
								ID:      "ruleset-foo",
								Name:    "Ruleset Foo",
								Version: "v1",
								Rules: []report.MergedRule{
									{
										ID:   "1",
										Name: "1",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"value1": {},
													"value2": {},
												},
											},
										},
									},
								},
							},
						},
					},
					{
						ID:         "provider-foo",
						Name:       "Provider Foo",
						DistinctBy: "id",
						Metadata: map[string]map[string]string{
							"foo": {
								"id":   "foo",
								"bar":  "foo",
								"time": "01-01-2000 00:00:00",
							},
							"bar": {
								"id":   "bar",
								"foo":  "bar",
								"time": "01-01-2000 00:00:00",
							},
						},
						Rulesets: []report.MergedRuleset{
							{
								ID:      "ruleset-foo",
								Name:    "Ruleset Foo",
								Version: "v1",
								Rules: []report.MergedRule{
									{
										ID:   "1",
										Name: "1",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
												},
											},
										},
									},
									{
										ID:   "2",
										Name: "2",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
													"bar": {},
												},
											},
											{
												Status:  "Failed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
												},
											},
										},
									},
									{
										ID:   "3",
										Name: "3",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"bar": {},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(mergedReport).To(Equal(expectedMergedReport))
			Expect(err).To(BeNil())
		})
		It("should correctly merge 2 reports when their metadata is different", func() {
			simpleReport2.Metadata = map[string]any{
				"bar": "foo",
			}
			reports := []*report.Report{&simpleReport1, &simpleReport2}
			mergedReport, err := report.MergeReport(reports, map[string]string{providerID: "id"})

			expectedMergedReport := &report.MergedReport{
				Time:        mergedReport.Time,
				MinStatus:   rule.Passed,
				DikiVersion: "1",
				Metadata:    map[string]any{},
				Providers: []report.MergedProvider{
					{
						ID:         "provider-foo",
						Name:       "Provider Foo",
						DistinctBy: "id",
						Metadata: map[string]map[string]string{
							"foo": {
								"id":   "foo",
								"bar":  "foo",
								"time": "01-01-2000 00:00:00",
							},
							"bar": {
								"id":   "bar",
								"foo":  "bar",
								"time": "01-01-2000 00:00:00",
							},
						},
						Rulesets: []report.MergedRuleset{
							{
								ID:      "ruleset-foo",
								Name:    "Ruleset Foo",
								Version: "v1",
								Rules: []report.MergedRule{
									{
										ID:   "1",
										Name: "1",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
												},
											},
										},
									},
									{
										ID:   "2",
										Name: "2",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
													"bar": {},
												},
											},
											{
												Status:  "Failed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
												},
											},
										},
									},
									{
										ID:   "3",
										Name: "3",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"bar": {},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(mergedReport).To(Equal(expectedMergedReport))
			Expect(err).To(BeNil())
		})
		It("should correctly merge 2 reports when their Diki version is different", func() {
			simpleReport2.DikiVersion = "2"
			reports := []*report.Report{&simpleReport1, &simpleReport2}
			mergedReport, err := report.MergeReport(reports, map[string]string{providerID: "id"})

			expectedMergedReport := &report.MergedReport{
				Time:        mergedReport.Time,
				MinStatus:   rule.Passed,
				DikiVersion: "This report was produced from reports generated by different Diki versions.",
				Metadata: map[string]any{
					"foo": "bar",
				},
				Providers: []report.MergedProvider{
					{
						ID:         "provider-foo",
						Name:       "Provider Foo",
						DistinctBy: "id",
						Metadata: map[string]map[string]string{
							"foo": {
								"id":   "foo",
								"bar":  "foo",
								"time": "01-01-2000 00:00:00",
							},
							"bar": {
								"id":   "bar",
								"foo":  "bar",
								"time": "01-01-2000 00:00:00",
							},
						},
						Rulesets: []report.MergedRuleset{
							{
								ID:      "ruleset-foo",
								Name:    "Ruleset Foo",
								Version: "v1",
								Rules: []report.MergedRule{
									{
										ID:   "1",
										Name: "1",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
												},
											},
										},
									},
									{
										ID:   "2",
										Name: "2",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
													"bar": {},
												},
											},
											{
												Status:  "Failed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"foo": {},
												},
											},
										},
									},
									{
										ID:   "3",
										Name: "3",
										Checks: []report.MergedCheck{
											{
												Status:  "Passed",
												Message: "foo",
												ReportsTargets: map[string][]rule.Target{
													"bar": {},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(mergedReport).To(Equal(expectedMergedReport))
			Expect(err).To(BeNil())
		})
	})
})
