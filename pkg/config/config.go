// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

// DikiConfig is used to represent Diki configuration file.
type DikiConfig struct {
	// Providers is a list of all known providers.
	Providers []ProviderConfig `yaml:"providers"`
	// Output describes options related to diki's output configuration.
	Output *OutputConfig `yaml:"output,omitempty"`
}

// ProviderConfig is used to describe and configure a provider.
type ProviderConfig struct {
	// ID is the unique identifier of a provider.
	ID string `yaml:"id"`
	// Name is the user friendly name of a provider.
	Name string `yaml:"name"`
	// Metadata represents additional values used to describe a provider.
	Metadata map[string]string `yaml:"metadata"`
	// Rulesets represents ruleset specific configurations.
	Rulesets []RulesetConfig `yaml:"rulesets"`
	// Args are provider specific arguments that each provider should be able to parse.
	Args any `yaml:"args"`
}

// RulesetConfig is used to describe and configure a ruleset.
type RulesetConfig struct {
	// ID is the unique identifier of a ruleset.
	ID string `yaml:"id"`
	// Name is the user friendly name of a ruleset.
	Name string `yaml:"name"`
	// Version is the ruleset's version.
	Version string `yaml:"version"`
	// RuleOptions is used to provide per rule configurations.
	RuleOptions []RuleOptionsConfig `yaml:"ruleOptions"`
}

// RuleOptionsConfig represents per rule options.
type RuleOptionsConfig struct {
	// RuleID is the id of the rule.
	RuleID string `yaml:"ruleID"`
	// Skip is the rule's skip configuration.
	Skip *RuleOptionSkipConfig `yaml:"skip,omitempty"`
	// Args are rule specific arguments that each rule should be able to parse.
	Args any `yaml:"args,omitempty"`
}

// RuleOptionSkipConfig represents options allowing a rule skip.
type RuleOptionSkipConfig struct {
	// Enabled determines if a rule should be skipped or not.
	Enabled bool `yaml:"enabled"`
	// Justification represents the reason why a rule is skipped.
	Justification string `yaml:"justification"`
}

// OutputConfig represents output configurations.
type OutputConfig struct {
	// Path is the location which will be used to write a diki report.
	Path string `yaml:"path"`
	// MinStatus is the minimal status that diki will report.
	MinStatus string `yaml:"minStatus"`
}
