// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

type RuleOption interface {
	Options1000 |
		Options1001 |
		Options1002 |
		Options1003 |
		Options2000 |
		Options2007
}
