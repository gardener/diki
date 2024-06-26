// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package retryerrors_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/retryerrors"
)

var _ = Describe("retryerrors", func() {
	DescribeTable("#ContainerNotFoundOnNodeRegexp",
		func(s string, expectedResult bool) {
			Expect(retryerrors.ContainerNotFoundOnNodeRegexp.MatchString(s)).To(Equal(expectedResult))
		},
		Entry("Should match container not found", "command /bin/sh find /var/lib/kubelet/pods/container-id -type f not found", true),
		Entry("Should match container file not found", "command /bin/sh find /var/lib/kubelet/pods/container-id -type f No such file or directory", true),
		Entry("Should not match when it is not found", "command /bin/sh find /var/lib/kubelet/pods/container-id -type f found", false),
		Entry("Should not match when it is not container path", "command /bin/sh find /var/foo -type f No such file or directory", false),
	)

	DescribeTable("#ContainerNotReadyRegexp",
		func(s string, expectedResult bool) {
			Expect(retryerrors.ContainerNotReadyRegexp.MatchString(s)).To(Equal(expectedResult))
		},
		Entry("Should match container not in status", "container with name foo not (yet) in status", true),
		Entry("Should match container not running", "container with name foo not (yet) running", true),
		Entry("Should not match unhandleable container", "cannot handle container with name foo", false),
		Entry("Should not match non containers", "bar with name foo not (yet) in status", false),
	)

	DescribeTable("#DikiDISAPodNotFoundRegexp",
		func(s string, expectedResult bool) {
			Expect(retryerrors.OpsPodNotFoundRegexp.MatchString(s)).To(Equal(expectedResult))
		},
		Entry("Should match diki pod not found", `pods "diki-111111-asdasdasda" not found`, true),
		Entry("Should not match when pod is not diki", `pods "foo" not found`, false),
		Entry("Should not match when pod does not fit diki pod regex", `pods "diki-1111-asdasdasda" not found`, false),
	)
})
