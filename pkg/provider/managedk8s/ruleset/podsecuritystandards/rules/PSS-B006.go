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
	_ rule.Rule              = &RulePSSB006{}
	_ rule.Severity          = &RulePSSB006{}
	_ option.Option          = &OptionsPSSB006{}
	_ option.MergeableOption = &OptionsPSSB006{}
)

type RulePSSB006 struct {
	Tbd any
}

// ID implements [rule.Rule].
func (r *RulePSSB006) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSB006) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSB006) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

// Severity implements [rule.Severity].
func (r *RulePSSB006) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

type OptionsPSSB006 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Validate implements [option.Option].
func (o *OptionsPSSB006) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSB006) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}
