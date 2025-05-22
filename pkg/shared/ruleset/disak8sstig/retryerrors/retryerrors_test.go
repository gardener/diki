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
		Entry("Should match container not found", "command /bin/sh /run/containerd/io.containerd.runtime.v2.task/k8s.io/id foo not found", true),
		Entry("Should not match when it is found", "command /bin/sh /run/containerd/io.containerd.runtime.v2.task/k8s.io/id foo found", false),
		Entry("Should not match when it is not container path", "command /bin/sh find /var/foo -type f not found", false),
	)

	DescribeTable("#ContainerFileNotFoundOnNodeRegexp",
		func(s string, expectedResult bool) {
			Expect(retryerrors.ContainerFileNotFoundOnNodeRegexp.MatchString(s)).To(Equal(expectedResult))
		},
		Entry("Should match container file not found", "command /bin/sh find /var/lib/kubelet/pods/container-id -type f No such file or directory", true),
		Entry("Should not match when it is found", "command /bin/sh find /var/lib/kubelet/pods/container-id -type f found", false),
		Entry("Should not match when it is not container file path", "command /bin/sh /run/containerd/io.containerd.runtime.v2.task/k8s.io/id foo No such file or directory", false),
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

	DescribeTable("#OpsPodNotFoundRegexp",
		func(s string, expectedResult bool) {
			Expect(retryerrors.OpsPodNotFoundRegexp.MatchString(s)).To(Equal(expectedResult))
		},
		Entry("Should match diki pod not found", `pods "diki-111111-asdasdasda" not found`, true),
		Entry("Should not match when pod is not diki", `pods "foo" not found`, false),
		Entry("Should not match when Pod does not fit diki pod regex", `pods "diki-1111-asdasdasda" not found`, false),
	)

	DescribeTable("#ObjectNotFoundRegexp",
		func(s string, expectedResult bool) {
			Expect(retryerrors.ObjectNotFoundRegexp.MatchString(s)).To(Equal(expectedResult))
		},
		Entry("Should match nerdctl object not found", `command /bin/sh /run/containerd/usr/local/bin/nerdctl 1 | jq -r .[0].Spec.mounts stderr output: msg="1 errors: [no such object 1]"`, true),
		Entry("Should not match when command is not nerdctl", `command /bin/sh /run/containerd/usr/local/bin/systemctl 1 stderr output: msg="1 errors: [no such object 1]`, false),
		Entry("Should not match when error is not not matched", `command /bin/sh /run/containerd/usr/local/bin/nerdctl 1 | jq -r .[0].Spec.mounts stderr output: msg="1 errors: [error object 1]`, false),
	)
})
