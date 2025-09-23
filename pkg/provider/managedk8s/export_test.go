// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package managedk8s

import "k8s.io/client-go/rest"

func SetInClusterConfigFunc(f func() (*rest.Config, error)) {
	inClusterConfigFunc = f
}
