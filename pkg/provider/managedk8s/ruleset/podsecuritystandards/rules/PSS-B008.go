// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule              = &RulePSSB008{}
	_ rule.Severity          = &RulePSSB008{}
	_ option.Option          = &OptionsPSSB008{}
	_ option.MergeableOption = &OptionsPSSB008{}
)

type RulePSSB008 struct {
	Tbd any
}

// ID implements [rule.Rule].
func (r *RulePSSB008) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSB008) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSB008) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

// Severity implements [rule.Severity].
func (r *RulePSSB008) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

type OptionsPSSB008 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Validate implements [option.Option].
func (o *OptionsPSSB008) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSB008) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}
