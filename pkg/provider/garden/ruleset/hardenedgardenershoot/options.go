// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package hardenedgardenershoot

import (
	"log/slog"

	"k8s.io/client-go/rest"
)

// CreateOption is a function that acts on a [Ruleset]
// and is used to construct such objects.
type CreateOption func(*Ruleset)

// WithVersion sets the version of a [Ruleset].
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

// WithConfig sets the Config of a [Ruleset].
func WithConfig(config *rest.Config) CreateOption {
	return func(r *Ruleset) {
		r.Config = config
	}
}

// WithArgs sets the args of a [Ruleset].
func WithArgs(args Args) CreateOption {
	return func(r *Ruleset) {
		switch {
		case args.MaxRetries == nil:
		case *args.MaxRetries < 0:
			panic("max retries should not be a negative number")
		default:
			r.args.MaxRetries = args.MaxRetries
		}

		if len(args.ProjectNamespace) == 0 {
			panic("project namespace should not be empty")
		}
		if len(args.ShootName) == 0 {
			panic("shoot name should not be empty")
		}

		r.args.ProjectNamespace = args.ProjectNamespace
		r.args.ShootName = args.ShootName
	}
}

// WithNumberOfWorkers sets the max number of Workers of a [Ruleset].
func WithNumberOfWorkers(numWorkers int) CreateOption {
	return func(r *Ruleset) {
		if numWorkers <= 0 {
			panic("number of workers should be a possitive number")
		}
		r.numWorkers = numWorkers
	}
}

// WithLogger the logger of a [Ruleset].
func WithLogger(logger *slog.Logger) CreateOption {
	return func(r *Ruleset) {
		r.logger = logger
	}
}
