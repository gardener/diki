// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

type RuleOption interface {
	Options2000 |
		Options2001 |
		Options2003 |
		Options2004 |
		Options2005 |
		Options2006 |
		Options2007 |
		Options2008
}
