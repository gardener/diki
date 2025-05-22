// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package retryerrors

import (
	"regexp"
)

var (
	// ContainerNotFoundOnNodeRegexp regex to match container on node not found
	ContainerNotFoundOnNodeRegexp = regexp.MustCompile(`(?i)(command /bin/sh /run/containerd.*not found)`)
	// ContainerFileNotFoundOnNodeRegexp regex to match container file path on node not found
	ContainerFileNotFoundOnNodeRegexp = regexp.MustCompile(`(?i)(command /bin/sh find.*No such file or directory)`)
	// ContainerNotReadyRegexp regex to match container not yet in status or not running
	ContainerNotReadyRegexp = regexp.MustCompile(`(?i)(container with name .* (not \(yet\) in status|not \(yet\) running))`)
	// OpsPodNotFoundRegexp regex to match ops pod not found for DISA K8s STIG ruleset
	OpsPodNotFoundRegexp = regexp.MustCompile(`(?i)(pods "diki-[\d]{6}-.{10}" not found)`)
	// ObjectNotFoundRegexp regex to match object not found by nerdctl
	ObjectNotFoundRegexp = regexp.MustCompile(`(?i)(command /bin/sh /.*/nerdctl .* \[no such object)`)
)
