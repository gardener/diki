// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package virtualgarden_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider/virtualgarden"
)

var _ = Describe("ValidateProviderConfig", func() {
	var fldPath *field.Path

	BeforeEach(func() {
		fldPath = field.NewPath("providers").Index(0)
	})

	It("should return no errors for a valid config", func() {
		conf := config.ProviderConfig{
			ID:   "virtualgarden",
			Name: "Virtual Garden",
			Args: map[string]string{
				"runtimeKubeconfigPath": "/path/to/kubeconfig",
			},
			Rulesets: []config.RulesetConfig{
				{ID: "disa-kubernetes-stig", Version: "v2r5"},
			},
		}

		errs := virtualgarden.ValidateProviderConfig(conf, fldPath)
		Expect(errs).To(BeEmpty())
	})

	It("should return error for unsupported ruleset ID", func() {
		conf := config.ProviderConfig{
			ID:   "virtualgarden",
			Name: "Virtual Garden",
			Args: map[string]string{
				"runtimeKubeconfigPath": "/path/to/kubeconfig",
			},
			Rulesets: []config.RulesetConfig{
				{ID: "unknown-ruleset", Version: "v1"},
			},
		}

		errs := virtualgarden.ValidateProviderConfig(conf, fldPath)
		Expect(errs).To(HaveLen(1))
		Expect(errs[0].Field).To(Equal("providers[0].rulesets[0].id"))
	})

	It("should return error for duplicate ruleset ID and version", func() {
		conf := config.ProviderConfig{
			ID:   "virtualgarden",
			Name: "Virtual Garden",
			Args: map[string]string{
				"runtimeKubeconfigPath": "/path/to/kubeconfig",
			},
			Rulesets: []config.RulesetConfig{
				{ID: "disa-kubernetes-stig", Version: "v2r5"},
				{ID: "disa-kubernetes-stig", Version: "v2r5"},
			},
		}

		errs := virtualgarden.ValidateProviderConfig(conf, fldPath)
		Expect(errs).To(HaveLen(1))
		Expect(errs[0].Field).To(Equal("providers[0].rulesets[1]"))
		Expect(errs[0].Type).To(Equal(field.ErrorTypeDuplicate))
	})

	It("should return error for missing required provider args", func() {
		conf := config.ProviderConfig{
			ID:   "virtualgarden",
			Name: "Virtual Garden",
			Args: map[string]any{},
		}

		errs := virtualgarden.ValidateProviderConfig(conf, fldPath)
		Expect(errs).To(HaveLen(1))
		Expect(errs[0].Type).To(Equal(field.ErrorTypeRequired))
		Expect(errs[0].Field).To(Equal("providers[0].args.runtimeKubeconfigPath"))
	})

	It("should return error for invalid args", func() {
		conf := config.ProviderConfig{
			ID:   "virtualgarden",
			Name: "Virtual Garden",
			Args: "not-a-map",
		}

		errs := virtualgarden.ValidateProviderConfig(conf, fldPath)
		Expect(errs).To(HaveLen(1))
		Expect(errs[0].Field).To(Equal("providers[0].args"))
	})
})
