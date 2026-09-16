// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package gardenlinux_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGardenlinux(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Gardenlinux Ruleset Suite")
}
