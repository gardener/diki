// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package managedk8s

func SetInClusterConfigFunc(f inClusterConfigGetter) {
	inClusterConfigFunc = f
}
