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
	_ rule.Rule              = &RulePSSR003{}
	_ rule.Severity          = &RulePSSR003{}
	_ option.Option          = &OptionsPSSR003{}
	_ option.MergeableOption = &OptionsPSSR003{}
)

type RulePSSR003 struct {
	Tbd any
}

// ID implements [rule.Rule].
func (r *RulePSSR003) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSR003) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSR003) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

// Severity implements [rule.Severity].
func (r *RulePSSR003) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

type OptionsPSSR003 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Validate implements [option.Option].
func (o *OptionsPSSR003) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSR003) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}
