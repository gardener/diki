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
	_ rule.Rule              = &RulePSSR005{}
	_ rule.Severity          = &RulePSSR005{}
	_ option.Option          = &OptionsPSSR005{}
	_ option.MergeableOption = &OptionsPSSR005{}
)

type RulePSSR005 struct {
	Tbd any
}

// ID implements [rule.Rule].
func (r *RulePSSR005) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSR005) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSR005) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

// Severity implements [rule.Severity].
func (r *RulePSSR005) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

type OptionsPSSR005 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Validate implements [option.Option].
func (o *OptionsPSSR005) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSR005) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}
