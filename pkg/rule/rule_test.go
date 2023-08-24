// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rule_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("rule", func() {
	DescribeTable("#Status.Less",
		func(s1, s2 rule.Status, expectedResult bool) {
			Expect(s1.Less(s2)).To(Equal(expectedResult))
		},
		Entry("Passed should be less than Accepted", rule.Passed, rule.Accepted, true),
		Entry("Accepted should not be less than Passed", rule.Accepted, rule.Passed, false),
	)
})
