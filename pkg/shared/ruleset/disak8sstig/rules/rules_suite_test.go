// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"log/slog"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/shared/provider"
)

var testLogger provider.Logger

func TestRules(t *testing.T) {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(handler)
	testLogger = logger
	RegisterFailHandler(Fail)
	RunSpecs(t, "DISA Kubernetes STIG rules Test Suite")
}
