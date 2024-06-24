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

// WithAdditionalOpsPodLabels sets the AdditionalOpsPodLabels of a [Ruleset].
func WithAdditionalOpsPodLabels(labels map[string]string) CreateOption {
	return func(r *Ruleset) {
		r.AdditionalOpsPodLabels = labels
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

// WithArgs sets the args of a Ruleset.
func WithArgs(args Args) CreateOption {
	return func(r *Ruleset) {
		switch {
		case args.NumWorkers < 0:
			panic("number of workers should not be a negative number")
		case args.NumWorkers > 0:
			r.args.NumWorkers = args.NumWorkers
		default:
			r.args.NumWorkers = 5
		}

		switch {
		case args.MaxRetries < 0:
			panic("max retries should not be a negative number")
		case args.MaxRetries > 0:
			r.args.MaxRetries = args.MaxRetries
		default:
			r.args.MaxRetries = 1
		}
	}
}

// WithLogger the logger of a Ruleset.
func WithLogger(logger *slog.Logger) CreateOption {
	return func(r *Ruleset) {
		r.logger = logger
	}
}
