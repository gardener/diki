// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package virtualgarden_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestVirtualGarden(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Provider VirtualGarden Suite")
}
