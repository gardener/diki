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
	_ rule.Rule              = &RulePSSB009{}
	_ rule.Severity          = &RulePSSB009{}
	_ option.Option          = &OptionsPSSB009{}
	_ option.MergeableOption = &OptionsPSSB009{}
)

type RulePSSB009 struct {
	Tbd any
}

// ID implements [rule.Rule].
func (r *RulePSSB009) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSB009) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSB009) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

// Severity implements [rule.Severity].
func (r *RulePSSB009) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

type OptionsPSSB009 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Validate implements [option.Option].
func (o *OptionsPSSB009) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSB009) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}
