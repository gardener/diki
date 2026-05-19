// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package ruleset_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/config"
	sharedruleset "github.com/gardener/diki/pkg/shared/ruleset"
)

var _ = Describe("Ruleset", func() {
	Describe("UnknownVersionError", func() {
		It("should return an error with the correct format", func() {
			err := sharedruleset.UnknownVersionError("disa-kubernetes-stig", "v99", "gardener")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("unknown ruleset disa-kubernetes-stig version: v99 - use 'diki show provider gardener' to see the provider's supported rulesets"))
		})
	})

	Describe("IndexRuleOptions", func() {
		It("should return an empty map for empty input", func() {
			indexed, err := sharedruleset.IndexRuleOptions(nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(indexed).To(BeEmpty())
		})

		It("should index rule options by rule ID", func() {
			ruleOptions := []config.RuleOptionsConfig{
				{RuleID: "rule-1", Args: "args1"},
				{RuleID: "rule-2", Args: "args2"},
				{RuleID: "rule-3", Args: "args3"},
			}

			indexed, err := sharedruleset.IndexRuleOptions(ruleOptions)
			Expect(err).NotTo(HaveOccurred())
			Expect(indexed).To(HaveLen(3))
			Expect(indexed["rule-1"].Index).To(Equal(0))
			Expect(indexed["rule-1"].RuleID).To(Equal("rule-1"))
			Expect(indexed["rule-2"].Index).To(Equal(1))
			Expect(indexed["rule-3"].Index).To(Equal(2))
		})

		It("should return an error for duplicate rule IDs", func() {
			ruleOptions := []config.RuleOptionsConfig{
				{RuleID: "rule-1", Args: "args1"},
				{RuleID: "rule-2", Args: "args2"},
				{RuleID: "rule-1", Args: "args3"},
			}

			indexed, err := sharedruleset.IndexRuleOptions(ruleOptions)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("rule option for rule id: rule-1 is already registered"))
			Expect(indexed).To(BeNil())
		})
	})
})
