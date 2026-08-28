// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"log/slog"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var testLogger *slog.Logger

func TestRules(t *testing.T) {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(handler)
	testLogger = logger
	RegisterFailHandler(Fail)
	RunSpecs(t, "DISA Kubernetes STIG rules Test Suite")
}
