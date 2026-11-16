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
	_ rule.Rule              = &RulePSSB002{}
	_ rule.Severity          = &RulePSSB002{}
	_ option.Option          = &OptionsPSSB002{}
	_ option.MergeableOption = &OptionsPSSB002{}
)

type RulePSSB002 struct {
	Tbd any
}

// Severity implements [rule.Severity].
func (r *RulePSSB002) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

// ID implements [rule.Rule].
func (r *RulePSSB002) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSB002) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSB002) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

type OptionsPSSB002 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSB002) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}

// Validate implements [option.Option].
func (o *OptionsPSSB002) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}
