// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package junitreportparser_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestJUnitReportParser(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "JUnit Test Parser Suite")
}
