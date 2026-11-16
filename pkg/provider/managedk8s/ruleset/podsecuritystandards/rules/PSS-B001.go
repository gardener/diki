// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule              = &RulePSSB001{}
	_ rule.Severity          = &RulePSSB001{}
	_ option.Option          = &OptionsPSSB001{}
	_ option.MergeableOption = &OptionsPSSB001{}
)

type RulePSSB001 struct {
	Client  client.Client
	Options *OptionsPSSB001
}

type OptionsPSSB001 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

// Severity implements [rule.Severity].
func (r *RulePSSB001) Severity() rule.SeverityLevel {
	panic("unimplemented")
}

// ID implements [rule.Rule].
func (r *RulePSSB001) ID() string {
	panic("unimplemented")
}

// Name implements [rule.Rule].
func (r *RulePSSB001) Name() string {
	panic("unimplemented")
}

// Run implements [rule.Rule].
func (r *RulePSSB001) Run(_ context.Context) (rule.RuleResult, error) {
	panic("unimplemented")
}

// Merge implements [option.MergeableOption].
func (o *OptionsPSSB001) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}

// Validate implements [option.Option].
func (o *OptionsPSSB001) Validate(_ *field.Path) field.ErrorList {
	panic("unimplemented")
}
