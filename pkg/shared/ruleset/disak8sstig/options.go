// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

// FileOptions contains files specific stat options
type FileOptions struct {
	ExpectedFileOwner ExpectedOwner `yaml:"expectedFileOwner"`
}

// ExpectedOwner contains expected user and group owners
type ExpectedOwner struct {
	Users  []string `yaml:"users"`
	Groups []string `yaml:"groups"`
}
