// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// Package mergetest provides shared Ginkgo assertions for [option.MergeableOption]
// implementations, factoring out the three cases that repeat verbatim across every
// per-type Merge test: nil-other returns the receiver, a wrong-type other returns
// an error, and a non-nil other of the same type is accepted.
//
// Type-specific happy-path assertions (which fields are unioned, concatenated, or
// overridden) stay inline in each Merge test because their expectations vary.
package mergetest

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

// AssertNilOtherReturnsReceiver spawns an It that verifies base.Merge(nil) returns
// base unchanged. Every MergeableOption implementation is expected to honour this.
func AssertNilOtherReturnsReceiver(base option.MergeableOption) {
	It("should return the receiver when merging with nil", func() {
		merged, err := base.Merge(nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(merged).To(BeIdenticalTo(base))
	})
}

// AssertWrongTypeErrors spawns an It that verifies base.Merge(wrongType) returns
// an error. Every MergeableOption implementation is expected to reject a mismatched
// other rather than silently ignore it.
func AssertWrongTypeErrors(base, wrongType option.MergeableOption) {
	It("should return error when merging with wrong type", func() {
		_, err := base.Merge(wrongType)
		Expect(err).To(HaveOccurred())
	})
}
