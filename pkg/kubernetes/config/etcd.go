// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

// EtcdConfig describes ETCD configuration values.
type EtcdConfig struct {
	ClientTransportSecurity TransportSecurity `yaml:"client-transport-security"`
	PeerTransportSecurity   TransportSecurity `yaml:"peer-transport-security"`
}

// TransportSecurity is the transport security configuration in an ETCD configuration.
type TransportSecurity struct {
	AutoTLS  *bool   `yaml:"auto-tls"`
	CertAuth *bool   `yaml:"client-cert-auth"`
	CertFile *string `yaml:"cert-file"`
	KeyFile  *string `yaml:"key-file"`
}
