// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package slogr

import (
	"context"
	"log/slog"

	"github.com/go-logr/logr"
)

var (
	_ logr.LogSink = &Slogr{}
)

// Slogr is a wrapper around [slog.Logger] to implement the [logr.LogSink] interface.
type Slogr struct {
	logger *slog.Logger
}

// NewLogr creates a new [logr.Logger] from a [slog.Logger].
func NewLogr(logger *slog.Logger) logr.Logger {
	return logr.New(Slogr{logger: logger})
}

// Enabled implmenents the [logr.LogSink] interface.
func (s Slogr) Enabled(level int) bool {
	return s.logger.Enabled(context.Background(), slog.Level(level))
}

// Error logs an error message.
func (s Slogr) Error(err error, msg string, keysAndValues ...any) {
	s.logger.Error(msg, append([]any{"error", err}, keysAndValues)...)
}

// Info logs an info message.
func (s Slogr) Info(_ int, msg string, keysAndValues ...any) {
	s.logger.Info(msg, keysAndValues...)
}

// Init implments the [logr.LogSink] interface.
func (s Slogr) Init(_ logr.RuntimeInfo) {
}

// WithName returns a new [logr.Logger] with the specified  group name.
func (s Slogr) WithName(name string) logr.LogSink {
	s.logger.WithGroup(name)
	return &s
}

// WithValues returns a new [logr.Logger] with the specified key-value pairs.
func (s Slogr) WithValues(keysAndValues ...any) logr.LogSink {
	s.logger = s.logger.With(keysAndValues...)
	return &s
}
