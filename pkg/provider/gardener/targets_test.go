// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gardener_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/rule"
)

var _ = Describe("targets", func() {
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
})
