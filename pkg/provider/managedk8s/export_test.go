// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package managedk8s

func SetInClusterConfigFunc(f inClusterConfigGetter) {
	inClusterConfigFunc = f
}
