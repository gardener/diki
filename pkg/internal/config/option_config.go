// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package config

import "github.com/gardener/diki/pkg/config"

// IndexedRuleOptionsConfig represents per rule options and the index at which the option is configured in the ruleOptions configuration.
type IndexedRuleOptionsConfig struct {
	config.RuleOptionsConfig
	// Index is the rule option's index in the ruleOptions configuration.
	Index int
}
