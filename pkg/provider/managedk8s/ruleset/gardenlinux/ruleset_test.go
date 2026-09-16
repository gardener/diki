// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package gardenlinux_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/gardenlinux"
)

var _ = Describe("ValidateRulesetConfig", func() {
	It("should accept a config without ruleOptions", func() {
		errs := gardenlinux.ValidateRulesetConfig(config.RulesetConfig{}, field.NewPath("rulesets").Index(0))
		Expect(errs).To(BeEmpty())
	})

	It("should accept a skip-only ruleOption with a justification", func() {
		rulesetConfig := config.RulesetConfig{
			RuleOptions: []config.RuleOptionsConfig{
				{RuleID: "1", Skip: &config.RuleOptionSkipConfig{Enabled: true, Justification: "not applicable"}},
			},
		}

		errs := gardenlinux.ValidateRulesetConfig(rulesetConfig, field.NewPath("rulesets").Index(0))
		Expect(errs).To(BeEmpty())
	})

	It("should require a ruleID", func() {
		rulesetConfig := config.RulesetConfig{
			RuleOptions: []config.RuleOptionsConfig{
				{Skip: &config.RuleOptionSkipConfig{Enabled: true, Justification: "x"}},
			},
		}

		errs := gardenlinux.ValidateRulesetConfig(rulesetConfig, field.NewPath("rulesets").Index(0))
		Expect(errs).To(HaveLen(1))
		Expect(errs[0].Type).To(Equal(field.ErrorTypeRequired))
		Expect(errs[0].Field).To(Equal("rulesets[0].ruleOptions[0].ruleID"))
	})

	It("should forbid per-rule args", func() {
		rulesetConfig := config.RulesetConfig{
			RuleOptions: []config.RuleOptionsConfig{
				{RuleID: "1", Args: map[string]any{"foo": "bar"}},
			},
		}

		errs := gardenlinux.ValidateRulesetConfig(rulesetConfig, field.NewPath("rulesets").Index(0))
		Expect(errs).To(HaveLen(1))
		Expect(errs[0].Type).To(Equal(field.ErrorTypeForbidden))
		Expect(errs[0].Field).To(Equal("rulesets[0].ruleOptions[0].args"))
	})
})
