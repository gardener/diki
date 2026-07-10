// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gardenlinux

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

// WithConfig sets the Config of a [Ruleset].
func WithConfig(config *rest.Config) CreateOption {
	return func(r *Ruleset) {
		r.Config = config
	}
}

// WithArgs sets the args of a [Ruleset].
func WithArgs(args Args) CreateOption {
	return func(r *Ruleset) {
		r.args = args
	}
}

// WithLogger sets the logger of a [Ruleset].
func WithLogger(logger *slog.Logger) CreateOption {
	return func(r *Ruleset) {
		r.logger = logger
	}
}
