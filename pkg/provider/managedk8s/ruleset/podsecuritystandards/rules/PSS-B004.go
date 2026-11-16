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
	_ rule.Rule              = &RulePSSB004{}
	_ rule.Severity          = &RulePSSB004{}
	_ option.Option          = &OptionsPSSB004{}
	_ option.MergeableOption = &OptionsPSSB004{}
)

type RulePSSB004 struct {
	Tbd any
}

// Severity implements [rule.Severity].
func (r *RulePSSB004) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

// ID implements [rule.Rule].
func (r *RulePSSB004) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSB004) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSB004) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

type OptionsPSSB004 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Validate implements [option.Option].
func (o *OptionsPSSB004) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSB004) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}
