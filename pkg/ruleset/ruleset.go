// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package ruleset

import (
	"context"

	"github.com/gardener/diki/pkg/rule"
)

// RulesetResult contains the results of Rule runs belonging to the same Ruleset.
type RulesetResult struct {
	RulesetID      string
	RulesetName    string
	RulesetVersion string
	RuleResults    []rule.RuleResult
}

// Ruleset is a set of Rules.
type Ruleset interface {
	ID() string
	Name() string
	Version() string
	Run(ctx context.Context) (RulesetResult, error)
	RunRule(ctx context.Context, id string) (rule.RuleResult, error)
}
