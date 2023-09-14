// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r10_test

import (
	"log/slog"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var testLogger *slog.Logger

func TestV1R10(t *testing.T) {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(handler)
	testLogger = logger
	RegisterFailHandler(Fail)
	RunSpecs(t, "DISA Kubernetes STIG V1R10 Test Suite")
}

func (r *FakeRandString) Generate(n int) string {
	b := make([]rune, n)
	for i := 0; i < n; i++ {
		b[i] = r.CurrentChar
	}
	r.CurrentChar++
	return string(b)
}

type FakeRandString struct {
	CurrentChar rune
}
