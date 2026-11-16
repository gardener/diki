// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package rules

import "github.com/gardener/diki/pkg/shared/kubernetes/option"

type RulePSSB011 struct {
	Tbd any
}

type OptionsPSSB011 struct {
	Tbd any `json:"tbd" yaml:"tbd"`
}

func (o *OptionsPSSB011) Merge(_ option.MergeableOption) (option.MergeableOption, error) {
	panic("unimplemented")
}
