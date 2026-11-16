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
	_ rule.Rule              = &RulePSSR002{}
	_ rule.Severity          = &RulePSSR002{}
	_ option.Option          = &OptionsPSSR002{}
	_ option.MergeableOption = &OptionsPSSR002{}
)

type RulePSSR002 struct {
	Tbd any
}

// Severity implements [rule.Severity].
func (r *RulePSSR002) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

// ID implements [rule.Rule].
func (r *RulePSSR002) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSR002) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSR002) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

type OptionsPSSR002 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSR002) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}

// Validate implements [option.Option].
func (o *OptionsPSSR002) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}
