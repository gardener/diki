// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

// KubeProxyConfig describes kube-proxy configuration values.
type KubeProxyConfig struct {
	ClientConnection KPClientConnection `yaml:"clientConnection" json:"clientConnection"`
	FeatureGates     map[string]bool    `yaml:"featureGates" json:"featureGates"`
}

// KPClientConnection describes kube-proxy configuration values for client connection.
type KPClientConnection struct {
	Kubeconfig string `yaml:"kubeconfig" json:"kubeconfig"`
}
