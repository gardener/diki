// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	"errors"
)

var (
	ErrShootClientNil      = errors.New("shoot client is nil")
	ErrSeedClientNil       = errors.New("seed client is nil")
	ErrShootNamespaceEmpty = errors.New("shoot namespace is empty")
)
