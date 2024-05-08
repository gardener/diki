// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gardener

import (
	"log/slog"

	"k8s.io/client-go/rest"
)

// CreateOption is a function that acts on a Provider
// and is used to construct such objects.
type CreateOption func(*Provider)

// WithID sets the id of a Provider.
func WithID(id string) CreateOption {
	return func(p *Provider) {
		p.id = id
	}
}

// WithName sets the name of a Provider.
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

// WithShootConfig sets the ShootConfig of a Provider.
func WithShootConfig(config *rest.Config) CreateOption {
	return func(p *Provider) {
		p.ShootConfig = config
	}
}

// WithSeedConfig sets the SeedConfig of a Provider.
func WithSeedConfig(config *rest.Config) CreateOption {
	return func(p *Provider) {
		p.SeedConfig = config
	}
}

// WithArgs sets the arguments of a Provider.
func WithArgs(args Args) CreateOption {
	return func(p *Provider) {
		p.Args = args
	}
}

// WithMetadata sets the metadata of a Provider.
func WithMetadata(metadata map[string]string) CreateOption {
	return func(p *Provider) {
		p.metadata = metadata
	}
}

// WithLogger sets the logger of a Provider.
func WithLogger(logger *slog.Logger) CreateOption {
	return func(p *Provider) {
		p.logger = logger
	}
}
