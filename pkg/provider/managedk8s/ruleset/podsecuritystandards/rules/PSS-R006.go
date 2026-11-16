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
	_ rule.Rule              = &RulePSSR006{}
	_ rule.Severity          = &RulePSSR006{}
	_ option.Option          = &OptionsPSSR006{}
	_ option.MergeableOption = &OptionsPSSR006{}
)

type RulePSSR006 struct {
	Tbd any
}

// Severity implements [rule.Severity].
func (r *RulePSSR006) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

// ID implements [rule.Rule].
func (r *RulePSSR006) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSR006) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSR006) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

type OptionsPSSR006 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSR006) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}

// Validate implements [option.Option].
func (o *OptionsPSSR006) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}
