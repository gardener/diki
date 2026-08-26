// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package ruleset_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSharedRuleset(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Shared Ruleset Test Suite")
}
