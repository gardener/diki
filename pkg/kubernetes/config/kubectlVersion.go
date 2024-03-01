// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

import "k8s.io/apimachinery/pkg/version"

// KubectlVersion contains the kubectl version info.
type KubectlVersion struct {
	ClientVersion version.Info `yaml:"clientVersion" json:"clientVersion"`
}
