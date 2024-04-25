// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package virtualgarden

import (
	"log/slog"

	"k8s.io/client-go/rest"
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

// WithOpsPodLabels sets the OpsPodLabels of a [Provider].
func WithOpsPodLabels(labels map[string]string) CreateOption {
	return func(p *Provider) {
		p.OpsPodLabels = labels
	}
}

// WithRuntimeConfig sets the ShootConfig of a [Provider].
func WithRuntimeConfig(config *rest.Config) CreateOption {
	return func(p *Provider) {
		p.RuntimeConfig = config
	}
}

// WithMetadata sets the metadata of a [Provider].
func WithMetadata(metadata map[string]string) CreateOption {
	return func(p *Provider) {
		p.metadata = metadata
	}
}

// WithLogger sets the logger of a [Provider].
func WithLogger(logger *slog.Logger) CreateOption {
	return func(p *Provider) {
		p.logger = logger
	}
}
