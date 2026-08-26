// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package merge_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMerge(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Merge Test Suite")
}
