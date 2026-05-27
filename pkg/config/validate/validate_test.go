// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validate_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/config/validate"
	"github.com/gardener/diki/pkg/provider"
)

var _ = Describe("ValidateConfig", func() {
	var validateFuncs map[string]provider.ValidateConfigFunc

	BeforeEach(func() {
		validateFuncs = map[string]provider.ValidateConfigFunc{
			"foo": func(_ config.ProviderConfig, _ *field.Path) field.ErrorList { return nil },
		}
	})

	It("should accept a valid output minStatus", func() {
		conf := &config.DikiConfig{
			Output: &config.OutputConfig{MinStatus: "Passed"},
		}

		Expect(validate.ValidateConfig(conf, validateFuncs)).To(BeEmpty())
	})

	It("should accept a missing output", func() {
		conf := &config.DikiConfig{}

		Expect(validate.ValidateConfig(conf, validateFuncs)).To(BeEmpty())
	})

	It("should accept an empty minStatus", func() {
		conf := &config.DikiConfig{
			Output: &config.OutputConfig{},
		}

		Expect(validate.ValidateConfig(conf, validateFuncs)).To(BeEmpty())
	})

	It("should reject an unknown minStatus", func() {
		conf := &config.DikiConfig{
			Output: &config.OutputConfig{MinStatus: "NotAStatus"},
		}

		errs := validate.ValidateConfig(conf, validateFuncs)
		Expect(errs).To(HaveLen(1))
		Expect(errs[0].Type).To(Equal(field.ErrorTypeNotSupported))
		Expect(errs[0].Field).To(Equal("output.minStatus"))
		Expect(errs[0].BadValue).To(Equal("NotAStatus"))
	})

	It("should reject a duplicate provider id", func() {
		conf := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{ID: "foo"},
				{ID: "foo"},
			},
		}

		errs := validate.ValidateConfig(conf, validateFuncs)
		Expect(errs).To(HaveLen(1))
		Expect(errs[0].Type).To(Equal(field.ErrorTypeDuplicate))
		Expect(errs[0].Field).To(Equal("providers[1].id"))
	})

	It("should reject an unknown provider id", func() {
		conf := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{ID: "unknown"},
			},
		}

		errs := validate.ValidateConfig(conf, validateFuncs)
		Expect(errs).To(HaveLen(1))
		Expect(errs[0].Type).To(Equal(field.ErrorTypeNotSupported))
		Expect(errs[0].Field).To(Equal("providers[0].id"))
	})
})
