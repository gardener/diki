// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package metadata

// Version is used to represent a specific version of a ruleset
type Version struct {
	// Version is the human-readable name of the ruleset release
	Version string `json:"version"`
	// Latest is a bool tag that showcases if the specific version is the latest one
	Latest bool `json:"latest"`
}

// RulesetMetadata is used to represent a specific ruleset and it's metadata
type RulesetMetadata struct {
	// RulesetID is the unique identifier of the ruleset
	RulesetID string `json:"rulesetID"`
	// RulesetName is the user-friendly name of the ruleset
	RulesetName string `json:"rulesetName"`
	// Versions is used to showcase the supported versions of the specific ruleset
	Versions []Version `json:"versions"`
}

// Provider is used to represent an available provider by it's name and unique identifier
type Provider struct {
	// ProviderID is the unique identifier of the provider
	ProviderID string `json:"id"`
	// ProviderName is the user-friendly name of the provider
	ProviderName string `json:"name"`
}

// ProviderMetadata is used to represent a specific provider and it's metadata
type ProviderMetadata struct {
	// ProviderID is the unique identifier of the provider
	ProviderID string `json:"providerID"`
	// ProviderName is the user-friendly name of the provider
	ProviderName string `json:"providerName"`
	// ProviderRulesets is a list of rulesets supported by the specific provider
	ProviderRulesets []RulesetMetadata `json:"rulesets"`
}
