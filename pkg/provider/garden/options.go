// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package garden

import (
	"k8s.io/client-go/rest"

	"github.com/gardener/diki/pkg/shared/provider"
)

// CreateOption is a function that acts on a [Provider]
// and is used to construct such objects.
type CreateOption func(*Provider)

// WithID sets the id of a [Provider].
func WithID(id string) CreateOption {
	return func(p *Provider) {
		p.id = id
	}
}

// WithName sets the name of a [Provider].
func WithName(name string) CreateOption {
	return func(p *Provider) {
		p.name = name
	}
}

// WithAdditionalOpsPodLabels sets the AdditionalOpsPodLabels of a [Provider].
func WithAdditionalOpsPodLabels(labels map[string]string) CreateOption {
	return func(p *Provider) {
		p.AdditionalOpsPodLabels = labels
	}
}

// WithConfig sets the Config of a [Provider].
func WithConfig(config *rest.Config) CreateOption {
	return func(p *Provider) {
		p.Config = config
	}
}

// WithMetadata sets the metadata of a [Provider].
func WithMetadata(metadata map[string]string) CreateOption {
	return func(p *Provider) {
		p.metadata = metadata
	}
}

// WithLogger sets the logger of a [Provider].
func WithLogger(logger provider.Logger) CreateOption {
	return func(p *Provider) {
		p.logger = logger
	}
}
