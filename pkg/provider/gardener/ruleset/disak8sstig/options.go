// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"log/slog"

	"k8s.io/client-go/rest"
)

// CreateOption is a function that acts on a Ruleset
// and is used to construct such objects.
type CreateOption func(*Ruleset)

// WithVersion sets the version of a Ruleset.
func WithVersion(version string) CreateOption {
	return func(r *Ruleset) {
		r.version = version
	}
}

// WithShootConfig sets the ShootConfig of a Ruleset.
func WithShootConfig(config *rest.Config) CreateOption {
	return func(r *Ruleset) {
		r.ShootConfig = config
	}
}

// WithSeedConfig sets the SeedConfig of a Ruleset.
func WithSeedConfig(config *rest.Config) CreateOption {
	return func(r *Ruleset) {
		r.SeedConfig = config
	}
}

// WithShootNamespace sets the shootNamespace of a Ruleset.
func WithShootNamespace(shootNamespace string) CreateOption {
	return func(r *Ruleset) {
		r.shootNamespace = shootNamespace
	}
}

// WithNumberOfWorkers sets the max number of Workers of a Ruleset.
func WithNumberOfWorkers(numWorkers int) CreateOption {
	return func(r *Ruleset) {
		if numWorkers <= 0 {
			panic("number of workers should be a possitive number")
		}
		r.numWorkers = numWorkers
	}
}

// WithLogger the logger of a Ruleset.
func WithLogger(logger *slog.Logger) CreateOption {
	return func(r *Ruleset) {
		r.logger = logger
	}
}
