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
	_ rule.Rule              = &RulePSSB003{}
	_ rule.Severity          = &RulePSSB003{}
	_ option.Option          = &OptionsPSSB003{}
	_ option.MergeableOption = &OptionsPSSB003{}
)

type RulePSSB003 struct {
	Tbd any
}

// Severity implements [rule.Severity].
func (r *RulePSSB003) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

// ID implements [rule.Rule].
func (r *RulePSSB003) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSB003) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSB003) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

type OptionsPSSB003 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSB003) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}

// Validate implements [option.Option].
func (o *OptionsPSSB003) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}
