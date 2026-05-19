// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package garden_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider/garden"
)

var _ = Describe("ValidateProviderConfig", func() {
	var fldPath *field.Path

	BeforeEach(func() {
		fldPath = field.NewPath("providers").Index(0)
	})

	It("should return no errors for a valid config", func() {
		conf := config.ProviderConfig{
			ID:   "garden",
			Name: "Garden",
			Args: map[string]string{
				"kubeconfigPath": "/path/to/kubeconfig",
			},
			Rulesets: []config.RulesetConfig{
				{
					ID:      "security-hardened-shoot-cluster",
					Version: "v0.2.1",
					Args:    map[string]string{"shootName": "my-shoot", "projectNamespace": "garden-my-project"},
				},
			},
		}

		errs := garden.ValidateProviderConfig(conf, fldPath)
		Expect(errs).To(BeEmpty())
	})

	It("should return error for unsupported ruleset ID", func() {
		conf := config.ProviderConfig{
			ID:   "garden",
			Name: "Garden",
			Args: map[string]any{},
			Rulesets: []config.RulesetConfig{
				{ID: "unknown-ruleset", Version: "v1"},
			},
		}

		errs := garden.ValidateProviderConfig(conf, fldPath)
		Expect(errs).To(HaveLen(1))
		Expect(errs[0].Field).To(Equal("providers[0].rulesets[0].id"))
	})

	It("should return error for duplicate ruleset ID and version", func() {
		conf := config.ProviderConfig{
			ID:   "garden",
			Name: "Garden",
			Args: map[string]any{},
			Rulesets: []config.RulesetConfig{
				{ID: "security-hardened-shoot-cluster", Version: "v0.2.1", Args: map[string]string{"shootName": "my-shoot", "projectNamespace": "garden-my-project"}},
				{ID: "security-hardened-shoot-cluster", Version: "v0.2.1", Args: map[string]string{"shootName": "my-shoot", "projectNamespace": "garden-my-project"}},
			},
		}

		errs := garden.ValidateProviderConfig(conf, fldPath)
		Expect(errs).To(HaveLen(1))
		Expect(errs[0].Field).To(Equal("providers[0].rulesets[1]"))
		Expect(errs[0].Type).To(Equal(field.ErrorTypeDuplicate))
	})

	It("should return error for missing required ruleset args", func() {
		conf := config.ProviderConfig{
			ID:   "garden",
			Name: "Garden",
			Args: map[string]any{},
			Rulesets: []config.RulesetConfig{
				{ID: "security-hardened-shoot-cluster", Version: "v0.2.1", Args: map[string]any{}},
			},
		}

		errs := garden.ValidateProviderConfig(conf, fldPath)
		Expect(errs).To(HaveLen(1))
		Expect(errs[0].Type).To(Equal(field.ErrorTypeInternal))
		Expect(errs[0].Error()).To(ContainSubstring("shootName"))
		Expect(errs[0].Error()).To(ContainSubstring("projectNamespace"))
	})

	It("should return error for invalid args", func() {
		conf := config.ProviderConfig{
			ID:   "garden",
			Name: "Garden",
			Args: "not-a-map",
		}

		errs := garden.ValidateProviderConfig(conf, fldPath)
		Expect(errs).To(HaveLen(1))
		Expect(errs[0].Field).To(Equal("providers[0].args"))
	})
})
