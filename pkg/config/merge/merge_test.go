// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package merge_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/config/merge"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

type mergeableOptions struct {
	Items []string `json:"items"`
}

var _ option.MergeableOption = &mergeableOptions{}

func (o *mergeableOptions) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	otherOpts, ok := other.(*mergeableOptions)
	if !ok {
		return nil, fmt.Errorf("cannot merge %T into *mergeableOptions", other)
	}
	merged := &mergeableOptions{
		Items: make([]string, 0, len(o.Items)+len(otherOpts.Items)),
	}
	merged.Items = append(merged.Items, o.Items...)
	merged.Items = append(merged.Items, otherOpts.Items...)
	return merged, nil
}

type nonMergeableOptions struct {
	Value string `json:"value"`
}

var _ = Describe("MergeConfigs", func() {
	var registry *merge.Registry

	BeforeEach(func() {
		registry = merge.NewRegistry()
		merge.RegisterMergeFunc[mergeableOptions](registry, merge.RegistryKey{
			ProviderID: "test-provider",
			RulesetID:  "test-ruleset",
			Version:    "v1.0",
			RuleID:     "rule-mergeable",
		})
		merge.RegisterMergeFunc[nonMergeableOptions](registry, merge.RegistryKey{
			ProviderID: "test-provider",
			RulesetID:  "test-ruleset",
			Version:    "v1.0",
			RuleID:     "rule-nonmergeable",
		})
	})

	It("should return custom config when base is nil", func() {
		custom := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{ID: "test-provider"},
			},
		}

		result, err := merge.MergeConfigs(nil, custom, registry)
		Expect(err).ToNot(HaveOccurred())
		Expect(result).To(Equal(custom))
	})

	It("should return nil when custom is nil", func() {
		base := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{ID: "test-provider"},
			},
		}

		result, err := merge.MergeConfigs(base, nil, registry)
		Expect(err).ToNot(HaveOccurred())
		Expect(result).To(BeNil())
	})

	It("should pass through custom provider unchanged when base has no matching provider", func() {
		base := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{ID: "other-provider"},
			},
		}
		custom := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-1", Args: map[string]any{"value": "custom"}},
							},
						},
					},
				},
			},
		}

		result, err := merge.MergeConfigs(base, custom, registry)
		Expect(err).ToNot(HaveOccurred())
		Expect(result.Providers[0].Rulesets[0].RuleOptions).To(HaveLen(1))
		Expect(result.Providers[0].Rulesets[0].RuleOptions[0].RuleID).To(Equal("rule-1"))
	})

	It("should pass through custom ruleset unchanged when base has no matching ruleset", func() {
		base := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{ID: "other-ruleset", Version: "v1.0"},
					},
				},
			},
		}
		custom := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-1", Args: map[string]any{"value": "custom"}},
							},
						},
					},
				},
			},
		}

		result, err := merge.MergeConfigs(base, custom, registry)
		Expect(err).ToNot(HaveOccurred())
		Expect(result.Providers[0].Rulesets[0].RuleOptions).To(HaveLen(1))
		Expect(result.Providers[0].Rulesets[0].RuleOptions[0].RuleID).To(Equal("rule-1"))
	})

	It("should keep custom-only rules as-is", func() {
		base := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:          "test-ruleset",
							Version:     "v1.0",
							RuleOptions: []config.RuleOptionsConfig{},
						},
					},
				},
			},
		}
		custom := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-custom-only", Args: map[string]any{"key": "val"}},
							},
						},
					},
				},
			},
		}

		result, err := merge.MergeConfigs(base, custom, registry)
		Expect(err).ToNot(HaveOccurred())
		Expect(result.Providers[0].Rulesets[0].RuleOptions).To(HaveLen(1))
		Expect(result.Providers[0].Rulesets[0].RuleOptions[0].RuleID).To(Equal("rule-custom-only"))
	})

	It("should append base-only rules to the output", func() {
		base := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-base-only", Args: map[string]any{"key": "base"}},
							},
						},
					},
				},
			},
		}
		custom := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:          "test-ruleset",
							Version:     "v1.0",
							RuleOptions: []config.RuleOptionsConfig{},
						},
					},
				},
			},
		}

		result, err := merge.MergeConfigs(base, custom, registry)
		Expect(err).ToNot(HaveOccurred())
		Expect(result.Providers[0].Rulesets[0].RuleOptions).To(HaveLen(1))
		Expect(result.Providers[0].Rulesets[0].RuleOptions[0].RuleID).To(Equal("rule-base-only"))
		Expect(result.Providers[0].Rulesets[0].RuleOptions[0].Args).To(Equal(map[string]any{"key": "base"}))
	})

	It("should use custom args when rule exists in both but is not mergeable", func() {
		base := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-nonmergeable", Args: map[string]any{"value": "base"}},
							},
						},
					},
				},
			},
		}
		custom := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-nonmergeable", Args: map[string]any{"value": "custom"}},
							},
						},
					},
				},
			},
		}

		result, err := merge.MergeConfigs(base, custom, registry)
		Expect(err).ToNot(HaveOccurred())
		Expect(result.Providers[0].Rulesets[0].RuleOptions).To(HaveLen(1))
		Expect(result.Providers[0].Rulesets[0].RuleOptions[0].Args).To(Equal(map[string]any{"value": "custom"}))
	})

	It("should merge args when rule implements MergeableOption", func() {
		base := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-mergeable", Args: map[string]any{"items": []any{"base-item"}}},
							},
						},
					},
				},
			},
		}
		custom := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-mergeable", Args: map[string]any{"items": []any{"custom-item"}}},
							},
						},
					},
				},
			},
		}

		result, err := merge.MergeConfigs(base, custom, registry)
		Expect(err).ToNot(HaveOccurred())
		Expect(result.Providers[0].Rulesets[0].RuleOptions).To(HaveLen(1))
		mergedArgs := result.Providers[0].Rulesets[0].RuleOptions[0].Args
		mergedMap, ok := mergedArgs.(map[string]any)
		Expect(ok).To(BeTrue())
		items, ok := mergedMap["items"].([]any)
		Expect(ok).To(BeTrue())
		Expect(items).To(ConsistOf("base-item", "custom-item"))
	})

	It("should use custom args when rule is not in registry", func() {
		base := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-unknown", Args: map[string]any{"value": "base"}},
							},
						},
					},
				},
			},
		}
		custom := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-unknown", Args: map[string]any{"value": "custom"}},
							},
						},
					},
				},
			},
		}

		result, err := merge.MergeConfigs(base, custom, registry)
		Expect(err).ToNot(HaveOccurred())
		Expect(result.Providers[0].Rulesets[0].RuleOptions[0].Args).To(Equal(map[string]any{"value": "custom"}))
	})

	Context("skip handling", func() {
		It("should skip when base skips a rule", func() {
			base := &config.DikiConfig{
				Providers: []config.ProviderConfig{
					{
						ID: "test-provider",
						Rulesets: []config.RulesetConfig{
							{
								ID:      "test-ruleset",
								Version: "v1.0",
								RuleOptions: []config.RuleOptionsConfig{
									{
										RuleID: "rule-nonmergeable",
										Skip:   &config.RuleOptionSkipConfig{Enabled: true, Justification: "base skip reason"},
										Args:   map[string]any{"value": "base"},
									},
								},
							},
						},
					},
				},
			}
			custom := &config.DikiConfig{
				Providers: []config.ProviderConfig{
					{
						ID: "test-provider",
						Rulesets: []config.RulesetConfig{
							{
								ID:      "test-ruleset",
								Version: "v1.0",
								RuleOptions: []config.RuleOptionsConfig{
									{RuleID: "rule-nonmergeable", Args: map[string]any{"value": "custom"}},
								},
							},
						},
					},
				},
			}

			result, err := merge.MergeConfigs(base, custom, registry)
			Expect(err).ToNot(HaveOccurred())
			Expect(result.Providers[0].Rulesets[0].RuleOptions[0].Skip).ToNot(BeNil())
			Expect(result.Providers[0].Rulesets[0].RuleOptions[0].Skip.Enabled).To(BeTrue())
			Expect(result.Providers[0].Rulesets[0].RuleOptions[0].Skip.Justification).To(Equal("base skip reason"))
		})

		It("should skip when custom skips a rule", func() {
			base := &config.DikiConfig{
				Providers: []config.ProviderConfig{
					{
						ID: "test-provider",
						Rulesets: []config.RulesetConfig{
							{
								ID:      "test-ruleset",
								Version: "v1.0",
								RuleOptions: []config.RuleOptionsConfig{
									{RuleID: "rule-nonmergeable", Args: map[string]any{"value": "base"}},
								},
							},
						},
					},
				},
			}
			custom := &config.DikiConfig{
				Providers: []config.ProviderConfig{
					{
						ID: "test-provider",
						Rulesets: []config.RulesetConfig{
							{
								ID:      "test-ruleset",
								Version: "v1.0",
								RuleOptions: []config.RuleOptionsConfig{
									{
										RuleID: "rule-nonmergeable",
										Skip:   &config.RuleOptionSkipConfig{Enabled: true, Justification: "custom skip reason"},
										Args:   map[string]any{"value": "custom"},
									},
								},
							},
						},
					},
				},
			}

			result, err := merge.MergeConfigs(base, custom, registry)
			Expect(err).ToNot(HaveOccurred())
			Expect(result.Providers[0].Rulesets[0].RuleOptions[0].Skip).ToNot(BeNil())
			Expect(result.Providers[0].Rulesets[0].RuleOptions[0].Skip.Enabled).To(BeTrue())
			Expect(result.Providers[0].Rulesets[0].RuleOptions[0].Skip.Justification).To(Equal("custom skip reason"))
		})

		It("should prefer custom justification when both skip", func() {
			base := &config.DikiConfig{
				Providers: []config.ProviderConfig{
					{
						ID: "test-provider",
						Rulesets: []config.RulesetConfig{
							{
								ID:      "test-ruleset",
								Version: "v1.0",
								RuleOptions: []config.RuleOptionsConfig{
									{
										RuleID: "rule-nonmergeable",
										Skip:   &config.RuleOptionSkipConfig{Enabled: true, Justification: "base reason"},
									},
								},
							},
						},
					},
				},
			}
			custom := &config.DikiConfig{
				Providers: []config.ProviderConfig{
					{
						ID: "test-provider",
						Rulesets: []config.RulesetConfig{
							{
								ID:      "test-ruleset",
								Version: "v1.0",
								RuleOptions: []config.RuleOptionsConfig{
									{
										RuleID: "rule-nonmergeable",
										Skip:   &config.RuleOptionSkipConfig{Enabled: true, Justification: "custom reason"},
									},
								},
							},
						},
					},
				},
			}

			result, err := merge.MergeConfigs(base, custom, registry)
			Expect(err).ToNot(HaveOccurred())
			Expect(result.Providers[0].Rulesets[0].RuleOptions[0].Skip.Justification).To(Equal("custom reason"))
		})
	})

	It("should preserve custom rule ordering and append base-only rules at the end", func() {
		base := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-base-1"},
								{RuleID: "rule-both"},
								{RuleID: "rule-base-2"},
							},
						},
					},
				},
			},
		}
		custom := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-custom-1"},
								{RuleID: "rule-both"},
								{RuleID: "rule-custom-2"},
							},
						},
					},
				},
			},
		}

		result, err := merge.MergeConfigs(base, custom, registry)
		Expect(err).ToNot(HaveOccurred())
		ruleIDs := make([]string, 0, len(result.Providers[0].Rulesets[0].RuleOptions))
		for _, opt := range result.Providers[0].Rulesets[0].RuleOptions {
			ruleIDs = append(ruleIDs, opt.RuleID)
		}
		Expect(ruleIDs).To(Equal([]string{"rule-custom-1", "rule-both", "rule-custom-2", "rule-base-1", "rule-base-2"}))
	})

	It("should use base args when custom args is nil but base has args", func() {
		base := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-nonmergeable", Args: map[string]any{"value": "base"}},
							},
						},
					},
				},
			},
		}
		custom := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-nonmergeable"},
							},
						},
					},
				},
			},
		}

		result, err := merge.MergeConfigs(base, custom, registry)
		Expect(err).ToNot(HaveOccurred())
		Expect(result.Providers[0].Rulesets[0].RuleOptions[0].Args).To(Equal(map[string]any{"value": "base"}))
	})

	It("should not match rulesets with different versions", func() {
		base := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v2.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-base", Args: map[string]any{"from": "base"}},
							},
						},
					},
				},
			},
		}
		custom := &config.DikiConfig{
			Providers: []config.ProviderConfig{
				{
					ID: "test-provider",
					Rulesets: []config.RulesetConfig{
						{
							ID:      "test-ruleset",
							Version: "v1.0",
							RuleOptions: []config.RuleOptionsConfig{
								{RuleID: "rule-custom", Args: map[string]any{"from": "custom"}},
							},
						},
					},
				},
			},
		}

		result, err := merge.MergeConfigs(base, custom, registry)
		Expect(err).ToNot(HaveOccurred())
		Expect(result.Providers[0].Rulesets[0].RuleOptions).To(HaveLen(1))
		Expect(result.Providers[0].Rulesets[0].RuleOptions[0].RuleID).To(Equal("rule-custom"))
	})
})

var _ = Describe("Registry", func() {
	It("should return nil for unregistered key", func() {
		registry := merge.NewRegistry()
		fn := registry.Get(merge.RegistryKey{ProviderID: "x", RulesetID: "y", Version: "z", RuleID: "w"})
		Expect(fn).To(BeNil())
	})

	It("should register and retrieve a merge function", func() {
		registry := merge.NewRegistry()
		merge.RegisterMergeFunc[mergeableOptions](registry, merge.RegistryKey{
			ProviderID: "p",
			RulesetID:  "r",
			Version:    "v",
			RuleID:     "rule",
		})

		fn := registry.Get(merge.RegistryKey{ProviderID: "p", RulesetID: "r", Version: "v", RuleID: "rule"})
		Expect(fn).ToNot(BeNil())

		result, err := fn(
			map[string]any{"items": []any{"a"}},
			map[string]any{"items": []any{"b"}},
		)
		Expect(err).ToNot(HaveOccurred())
		merged, ok := result.(map[string]any)
		Expect(ok).To(BeTrue())
		items, ok := merged["items"].([]any)
		Expect(ok).To(BeTrue())
		Expect(items).To(Equal([]any{"a", "b"}))
	})

	It("should return custom args for non-mergeable options", func() {
		registry := merge.NewRegistry()
		merge.RegisterMergeFunc[nonMergeableOptions](registry, merge.RegistryKey{
			ProviderID: "p",
			RulesetID:  "r",
			Version:    "v",
			RuleID:     "rule",
		})

		fn := registry.Get(merge.RegistryKey{ProviderID: "p", RulesetID: "r", Version: "v", RuleID: "rule"})
		Expect(fn).ToNot(BeNil())

		customArgs := map[string]any{"value": "custom"}
		result, err := fn(
			map[string]any{"value": "base"},
			customArgs,
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(result).To(Equal(customArgs))
	})
})
