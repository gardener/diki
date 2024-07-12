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

	Describe("#Target", func() {
		It("should correctly initialize", func() {
			t := rule.NewTarget("foo", "bar", "one", "two")
			Expect(t["foo"]).To(Equal("bar"))
			Expect(t["one"]).To(Equal("two"))
			Expect(len(t)).To(Equal(2))
		})

		It("should not modify the original target", func() {
			t := rule.NewTarget("foo", "bar", "one", "two")
			_ = t.With("1", "2")
			Expect(t["foo"]).To(Equal("bar"))
			Expect(t["one"]).To(Equal("two"))
			Expect(len(t)).To(Equal(2))
		})

		It("should add additional key values to target", func() {
			t := rule.NewTarget("foo", "bar", "one", "two")
			tt := t.With("1", "2")
			Expect(tt["foo"]).To(Equal("bar"))
			Expect(tt["one"]).To(Equal("two"))
			Expect(tt["1"]).To(Equal("2"))
			Expect(len(tt)).To(Equal(3))
		})

		It("should overwrite the values only in the new target", func() {
			t := rule.NewTarget("foo", "bar", "one", "two")
			tt := t.With("foo", "newbar")

			Expect(t["foo"]).To(Equal("bar"))
			Expect(t["one"]).To(Equal("two"))
			Expect(len(t)).To(Equal(2))

			Expect(tt["foo"]).To(Equal("newbar"))
			Expect(tt["one"]).To(Equal("two"))
			Expect(len(tt)).To(Equal(2))
		})
	})

	Describe("StatusIcon", func() {
		It("should not return white circle for supported statuses", func() {
			statuses := rule.Statuses()

			for _, status := range statuses {
				statusIcon := rule.StatusIcon(status)
				Expect(statusIcon).To(Not(Equal('⚪')))
			}
		})

		It("should return white circle for unsupported statuses", func() {
			var status rule.Status = "unsupportedStatus"

			statusIcon := rule.StatusIcon(status)
			Expect(statusIcon).To((Equal('⚪')))
		})
	})

	Describe("StatusDescription", func() {
		It("should not return Unknown description for supported statuses", func() {
			statuses := rule.Statuses()

			for _, status := range statuses {
				statusDescription := rule.StatusDescription(status)
				Expect(statusDescription).To(Not(Equal("Unknown")))
			}
		})

		It("should return Unknown description for unsupported statuses", func() {
			var status rule.Status = "unsupportedStatus"

			statusDescription := rule.StatusDescription(status)
			Expect(statusDescription).To((Equal("Unknown")))
		})
	})
})
