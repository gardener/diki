// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package retryerrors

import (
	"regexp"
)

var (
	// ContainerNotFoundOnNodeRegexp regex to match container path on node not found
	ContainerNotFoundOnNodeRegexp = regexp.MustCompile(`(?i)(/var/lib/kubelet/pods.*(No such file or directory|not found))`)
	// ContainerNotReadyRegexp regex to match container not yet in status or not running
	ContainerNotReadyRegexp = regexp.MustCompile(`(?i)(container with name .* (not \(yet\) in status|not \(yet\) running))`)
	// OpsPodNotFoundRegexp regex to match ops pod not found for DISA K8s STIG ruleset
	OpsPodNotFoundRegexp = regexp.MustCompile(`(?i)(pods "diki-[\d]{6}-.{10}" not found)`)
)
