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
	_ rule.Rule              = &RulePSSB005{}
	_ rule.Severity          = &RulePSSB005{}
	_ option.Option          = &OptionsPSSB005{}
	_ option.MergeableOption = &OptionsPSSB005{}
)

type RulePSSB005 struct {
	Tbd any
}

// Severity implements [rule.Severity].
func (r *RulePSSB005) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

// ID implements [rule.Rule].
func (r *RulePSSB005) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSB005) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSB005) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

type OptionsPSSB005 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSB005) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}

// Validate implements [option.Option].
func (o *OptionsPSSB005) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}
