// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestV1R11(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "DISA Kubernetes STIG V1R11 Test Suite")
}
