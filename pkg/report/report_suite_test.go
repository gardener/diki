// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestReport(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Report Test Suite")
}
