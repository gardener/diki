// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

// NodeConfigz contains the runtime kubelet config.
type NodeConfigz struct {
	KubeletConfig KubeletConfig `yaml:"kubeletconfig" json:"kubeletconfig"`
}

// KubeletConfig describes kubelet configuration values.
type KubeletConfig struct {
	Authentication                 KubeletAuthentication `yaml:"authentication" json:"authentication"`
	Authorization                  KubeletAuthorization  `yaml:"authorization" json:"authorization"`
	MaxPods                        *int32                `yaml:"maxPods" json:"maxPods"`
	ReadOnlyPort                   *int32                `yaml:"readOnlyPort" json:"readOnlyPort"`
	ServerTLSBootstrap             *bool                 `yaml:"serverTLSBootstrap" json:"serverTLSBootstrap"`
	StaticPodPath                  *string               `yaml:"staticPodPath" json:"staticPodPath"`
	TLSPrivateKeyFile              *string               `yaml:"tlsPrivateKeyFile" json:"tlsPrivateKeyFile"`
	TLSCertFile                    *string               `yaml:"tlsCertFile" json:"tlsCertFile"`
	FeatureGates                   map[string]bool       `yaml:"featureGates" json:"featureGates"`
	ProtectKernelDefaults          *bool                 `yaml:"protectKernelDefaults" json:"protectKernelDefaults"`
	StreamingConnectionIdleTimeout *string               `yaml:"streamingConnectionIdleTimeout" json:"streamingConnectionIdleTimeout"`
}

// KubeletAuthentication describes kubelet configuration values for authentication mechanisms.
type KubeletAuthentication struct {
	Anonymous KubeletAnonymousAuthentication `yaml:"anonymous" json:"anonymous"`
	X509      KubeletX509Authentication      `yaml:"x509" json:"x509"`
}

// KubeletAnonymousAuthentication describes kubelet configuration values for anonymous authentication.
type KubeletAnonymousAuthentication struct {
	Enabled *bool `yaml:"enabled" json:"enabled"`
}

// KubeletX509Authentication describes kubelet configuration values for x509 client certificate authentication.
type KubeletX509Authentication struct {
	ClientCAFile *string `yaml:"clientCAFile" json:"clientCAFile"`
}

// KubeletAuthorization describes kubelet configuration values for authorization mechanisms.
type KubeletAuthorization struct {
	Mode *string `yaml:"mode" json:"mode"`
}
