// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package metadata

// Version is used to represent a specific version of a ruleset.
type Version struct {
	// Version is the name of the ruleset release.
	Version string `json:"version"`
	// Latest shows if the specific version is the latest one.
	Latest bool `json:"latest"`
}

// Ruleset is used to represent a specific ruleset and it's metadata.
type Ruleset struct {
	// ID is the unique identifier of the ruleset.
	ID string `json:"id"`
	// Name is the user-friendly name of the ruleset.
	Name string `json:"name"`
	// Versions is used to showcase the supported versions of the specific ruleset.
	Versions []Version `json:"versions"`
}

// Provider is used to represent an available provider by it's name and unique identifier.
type Provider struct {
	// ID is the unique identifier of the provider.
	ID string `json:"id"`
	// Name is the user-friendly name of the provider.
	Name string `json:"name"`
}

// ProviderDetailed is used to represent a specific provider and it's metadata.
type ProviderDetailed struct {
	Provider
	Rulesets []Ruleset `json:"rulesets"`
}

// MetadataFunc constructs a detailed Provider metadata object.
type MetadataFunc func() ProviderDetailed
