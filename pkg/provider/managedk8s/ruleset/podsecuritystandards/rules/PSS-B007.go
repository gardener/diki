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
	_ rule.Rule              = &RulePSSB007{}
	_ rule.Severity          = &RulePSSB007{}
	_ option.Option          = &OptionsPSSB007{}
	_ option.MergeableOption = &OptionsPSSB007{}
)

type RulePSSB007 struct {
	Tbd any
}

// Severity implements [rule.Severity].
func (r *RulePSSB007) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

// ID implements [rule.Rule].
func (r *RulePSSB007) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSB007) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSB007) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

type OptionsPSSB007 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSB007) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}

// Validate implements [option.Option].
func (o *OptionsPSSB007) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}
