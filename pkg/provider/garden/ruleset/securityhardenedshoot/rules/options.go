// SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
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
