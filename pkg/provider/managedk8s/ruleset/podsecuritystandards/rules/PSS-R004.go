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
	_ rule.Rule              = &RulePSSR004{}
	_ rule.Severity          = &RulePSSR004{}
	_ option.Option          = &OptionsPSSR004{}
	_ option.MergeableOption = &OptionsPSSR004{}
)

type RulePSSR004 struct {
	Tbd any
}

// Severity implements [rule.Severity].
func (r *RulePSSR004) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

// ID implements [rule.Rule].
func (r *RulePSSR004) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSR004) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSR004) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

type OptionsPSSR004 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSR004) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}

// Validate implements [option.Option].
func (o *OptionsPSSR004) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}
