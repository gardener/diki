// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package option

// NodeSelectorOptions contains configuration for node grouping
type NodeSelectorOptions struct {
	NodeLabelsSelector NodeLabelsSelector `json:"nodeLabelsSelector" yaml:"nodeLabelsSelector"`
}

// NodeLabelsSelector contains node labels used for grouping nodes
type NodeLabelsSelector struct {
	Labels []string `json:"labels" yaml:"labels"`
}

// FileOwnerOptions contains expected user and group owners for files
type FileOwnerOptions struct {
	ExpectedFileOwner ExpectedOwner `json:"expectedFileOwner" yaml:"expectedFileOwner"`
}

// ExpectedOwner contains expected user and group owners
type ExpectedOwner struct {
	Users  []string `json:"users" yaml:"users"`
	Groups []string `json:"groups" yaml:"groups"`
}
