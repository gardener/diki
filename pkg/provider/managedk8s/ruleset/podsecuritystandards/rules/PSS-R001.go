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
	_ rule.Rule              = &RulePSSR001{}
	_ rule.Severity          = &RulePSSR001{}
	_ option.Option          = &OptionsPSSR001{}
	_ option.MergeableOption = &OptionsPSSR001{}
)

type RulePSSR001 struct {
	Tbd any
}

// Severity implements [rule.Severity].
func (r *RulePSSR001) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

// ID implements [rule.Rule].
func (r *RulePSSR001) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSR001) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSR001) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

type OptionsPSSR001 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSR001) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}

// Validate implements [option.Option].
func (o *OptionsPSSR001) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}
