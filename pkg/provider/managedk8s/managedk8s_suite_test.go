// SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package managedk8s_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestManagedK8s(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Provider managedk8s Suite")
}
